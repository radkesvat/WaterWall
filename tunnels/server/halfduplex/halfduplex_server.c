#include "halfduplex_server.h"

#include "buffer_pool.h"
#include "wmutex.h"
#include "loggers/network_logger.h"
#include "pipe_line.h"
#include "shiftbuffer.h"
#include "tunnel.h"
#include "worker.h"

#define i_type hmap_cons_t                            // NOLINT
#define i_key  hash_t                                 // NOLINT
#define i_val  struct halfduplex_server_con_state_s * // NOLINT
#include "stc/hmap.h"

enum
{
    kHmapCap      = 16 * 4,
    kMaxBuffering = (65535 * 2)
};

enum connection_status
{
    kCsUnkown,
    kCsUploadInTable,
    kCsUploadDirect,
    kCsDownloadInTable,
    kCsDownloadDirect
};

typedef struct halfduplex_server_state_s
{
    wmutex_t upload_line_map_mutex;
    hmap_cons_t    upload_line_map;

    wmutex_t download_line_map_mutex;
    hmap_cons_t    download_line_map;

} halfduplex_server_state_t;

typedef struct halfduplex_server_con_state_s
{

    sbuf_t        *buffering;
    line_t                *upload_line;
    line_t                *download_line;
    line_t                *main_line;
    enum connection_status state;

    hash_t hash;
} halfduplex_server_con_state_t;

struct notify_argument_s
{
    tunnel_t *self;
    hash_t    hash;
    uint8_t   tid;
};

static void onMainLinePaused(void *_cstate)
{
    halfduplex_server_con_state_t *cstate = _cstate;

    pauseLineDownSide(cstate->upload_line);
}

static void onMainLineResumed(void *_cstate)
{
    halfduplex_server_con_state_t *cstate = _cstate;

    resumeLineDownSide(cstate->upload_line);
    resumeLineDownSide(cstate->download_line);
}

static void onDownloadLinePaused(void *_cstate)
{
    halfduplex_server_con_state_t *cstate = _cstate;
    pauseLineUpSide(cstate->main_line);
}

static void onDownloadLineResumed(void *_cstate)
{
    halfduplex_server_con_state_t *cstate = _cstate;
    resumeLineUpSide(cstate->main_line);
}

static void onUploadDirectLinePaused(void *_cstate)
{
    halfduplex_server_con_state_t *cstate = _cstate;
    pauseLineUpSide(cstate->main_line);
}

static void onUploadDirectLineResumed(void *_cstate)
{
    halfduplex_server_con_state_t *cstate = _cstate;
    resumeLineUpSide(cstate->main_line);
}

static void upStream(tunnel_t *self, context_t *c);

static void notifyDownloadLineIsReadyForBind(hash_t hash, tunnel_t *self, uint8_t this_tid)
{
    halfduplex_server_state_t *state = TSTATE(self);

    mutexLock(&(state->upload_line_map_mutex));

    hmap_cons_t_iter f_iter = hmap_cons_t_find(&(state->upload_line_map), hash);
    bool             found  = f_iter.ref != hmap_cons_t_end(&(state->upload_line_map)).ref;

    if (found)
    {
        // upload pair is found
        uint8_t tid_upload_line = (*f_iter.ref).second->upload_line->tid;
        if (this_tid != tid_upload_line)
        {
            mutexUnlock(&(state->upload_line_map_mutex));
            return;
        }
        halfduplex_server_con_state_t *upload_line_cstate = ((halfduplex_server_con_state_t *) ((*f_iter.ref).second));

        hmap_cons_t_erase_at(&(state->upload_line_map), f_iter);
        mutexUnlock(&(state->upload_line_map_mutex));

        mutexLock(&(state->download_line_map_mutex));
        f_iter = hmap_cons_t_find(&(state->download_line_map), hash);
        found  = f_iter.ref != hmap_cons_t_end(&(state->download_line_map)).ref;

        if (found)
        {
            // downlod pair is found
            uint8_t tid_download_line = (*f_iter.ref).second->download_line->tid;
            mutexUnlock(&(state->download_line_map_mutex));

            // a very rare case is when this_tid == tid_download_line

            LSTATE_DROP(upload_line_cstate->upload_line);

            pipeTo(self, upload_line_cstate->upload_line, tid_download_line);

            if (upload_line_cstate->buffering)
            {
                context_t *bctx = contextCreate(upload_line_cstate->upload_line);
                bctx->payload   = upload_line_cstate->buffering;
                pipeUpStream(bctx);
            }
            memoryFree(upload_line_cstate);
        }
        else
        {
            mutexUnlock(&(state->download_line_map_mutex));

            LSTATE_DROP(upload_line_cstate->upload_line);
            if (isDownPiped(upload_line_cstate->upload_line))
            {
                pipeDownStream(contextCreateFin(upload_line_cstate->upload_line));
            }
            else
            {
                self->dw->downStream(self->dw, contextCreateFin(upload_line_cstate->upload_line));
            }
            memoryFree(upload_line_cstate);
        }
    }
    else
    {
        mutexUnlock(&(state->upload_line_map_mutex));

        // the connection just closed
    }
}

static void callNotifyDownloadLineIsReadyForBind(wevent_t *ev)
{
    struct notify_argument_s *args = weventGetUserdata(ev);
    notifyDownloadLineIsReadyForBind(args->hash, args->self, args->tid);
    memoryFree(args);
}

// todo (rename+format) names are not meaningful at all!
static void upStream(tunnel_t *self, context_t *c)
{
    if (isUpPiped(c->line))
    {
        pipeUpStream(c);
        return;
    }

    halfduplex_server_state_t     *state  = TSTATE(self);
    halfduplex_server_con_state_t *cstate = CSTATE(c);
    if (c->payload != NULL)
    {
        assert(cstate != NULL);

        sbuf_t *buf = c->payload;

        switch (cstate->state)
        {

        case kCsUnkown: {

            if (cstate->buffering)
            {
                c->payload        = sbufAppendMerge(contextGetBufferPool(c), c->payload, cstate->buffering);
                cstate->buffering = NULL;
            }

            if (sbufGetBufLength(buf) < sizeof(uint64_t))
            {
                cstate->buffering = c->payload;
                c->payload        = NULL;
                contextDestroy(c);
                return;
            }
            const bool is_upload                   = (((uint8_t *) sbufGetRawPtr(c->payload))[0] & 0x80) == 0x0;
            ((uint8_t *) sbufGetMutablePtr(c->payload))[0] = (((uint8_t *) sbufGetRawPtr(c->payload))[0] & 0x7F);

            hash_t hash = 0x0;
            sbufReadUnAlignedUI64(c->payload, (uint64_t *) &hash);
            cstate->hash = hash;

            if (is_upload)
            {
                cstate->upload_line = c->line;
                mutexLock(&(state->download_line_map_mutex));
                hmap_cons_t_iter f_iter = hmap_cons_t_find(&(state->download_line_map), hash);
                bool             found  = f_iter.ref != hmap_cons_t_end(&(state->download_line_map)).ref;

                if (found)
                {
                    // pair is found
                    uint8_t tid_download_line = (*f_iter.ref).second->download_line->tid;

                    if (tid_download_line == c->line->tid)
                    {
                        line_t *download_line =
                            ((halfduplex_server_con_state_t *) ((*f_iter.ref).second))->download_line;
                        cstate->download_line = download_line;

                        halfduplex_server_con_state_t *download_line_cstate =
                            ((halfduplex_server_con_state_t *) ((*f_iter.ref).second));

                        hmap_cons_t_erase_at(&(state->download_line_map), f_iter);
                        mutexUnlock(&(state->download_line_map_mutex));
                        cstate->state = kCsUploadDirect;
                        setupLineUpSide(c->line, onUploadDirectLinePaused, cstate, onUploadDirectLineResumed);

                        assert(download_line_cstate->state == kCsDownloadInTable);

                        download_line_cstate->state       = kCsDownloadDirect;
                        download_line_cstate->upload_line = c->line;
                        setupLineUpSide(download_line, onDownloadLinePaused, download_line_cstate,
                                        onDownloadLineResumed);

                        line_t *main_line               = newLine(tid_download_line);
                        download_line_cstate->main_line = main_line;
                        cstate->main_line               = main_line;
                        setupLineDownSide(main_line, onMainLinePaused, download_line_cstate, onMainLineResumed);
                        lineLock(main_line);
                        self->up->upStream(self->up, contextCreateInit(main_line));

                        if (! lineIsAlive(main_line))
                        {
                            lineUnlock(main_line);
                            contextReusePayload(c);
                            contextDestroy(c);
                            return;
                        }

                        lineUnlock(main_line);
                        sbufShiftRight(c->payload, sizeof(uint64_t));
                        if (sbufGetBufLength(buf) > 0)
                        {
                            self->up->upStream(self->up, contextSwitchLine(c, main_line));
                            return;
                        }
                        contextReusePayload(c);
                    }
                    else
                    {
                        mutexUnlock(&(state->download_line_map_mutex));

                        CSTATE_DROP(c);
                        memoryFree(cstate);

                        pipeTo(self, c->line, tid_download_line);
                        pipeUpStream(c);
                        return; // piped to another worker which has waiting connections
                    }
                }
                else
                {
                    mutexUnlock(&(state->download_line_map_mutex));
                    cstate->state = kCsUploadInTable;

                    mutexLock(&(state->upload_line_map_mutex));
                    bool push_succeed = hmap_cons_t_insert(&(state->upload_line_map), hash, cstate).inserted;
                    mutexUnlock(&(state->upload_line_map_mutex));

                    if (! push_succeed)
                    {
                        LOGW("HalfDuplexServer: duplicate upload connection closed");
                        CSTATE_DROP(c);
                        contextReusePayload(c);
                        memoryFree(cstate);
                        if (isDownPiped(c->line))
                        {
                            pipeDownStream(contextCreateFinFrom(c));
                        }
                        else
                        {
                            self->dw->downStream(self->dw, contextCreateFinFrom(c));
                        }
                        contextDestroy(c);
                        return;
                    }

                    cstate->buffering = buf;
                    c->payload        = NULL;
                    // upload connection is waiting in the pool
                }
            }
            else
            {
                contextReusePayload(c);
                cstate->download_line = c->line;

                mutexLock(&(state->upload_line_map_mutex));
                hmap_cons_t_iter f_iter = hmap_cons_t_find(&(state->upload_line_map), hash);
                bool             found  = f_iter.ref != hmap_cons_t_end(&(state->upload_line_map)).ref;

                if (found)
                {
                    // pair is found
                    uint8_t tid_upload_line = (*f_iter.ref).second->upload_line->tid;

                    if (tid_upload_line == c->line->tid)
                    {
                        halfduplex_server_con_state_t *upload_line_cstate =
                            ((halfduplex_server_con_state_t *) ((*f_iter.ref).second));
                        hmap_cons_t_erase_at(&(state->upload_line_map), f_iter);
                        mutexUnlock(&(state->upload_line_map_mutex));
                        cstate->state       = kCsDownloadDirect;
                        cstate->upload_line = upload_line_cstate->upload_line;
                        setupLineUpSide(c->line, onDownloadLinePaused, cstate, onDownloadLineResumed);

                        assert(upload_line_cstate->state == kCsUploadInTable);

                        setupLineUpSide(upload_line_cstate->upload_line, onUploadDirectLinePaused, upload_line_cstate,
                                        onUploadDirectLineResumed);
                        upload_line_cstate->state         = kCsUploadDirect;
                        upload_line_cstate->download_line = c->line;

                        line_t *main_line             = newLine(tid_upload_line);
                        upload_line_cstate->main_line = main_line;
                        cstate->main_line             = main_line;
                        setupLineDownSide(main_line, onMainLinePaused, cstate, onMainLineResumed);
                        lineLock(main_line);
                        self->up->upStream(self->up, contextCreateInit(main_line));

                        if (! lineIsAlive(main_line))
                        {
                            lineUnlock(main_line);
                            contextDestroy(c);
                            return;
                        }
                        lineUnlock(main_line);

                        assert(upload_line_cstate->buffering);

                        if (sbufGetBufLength(upload_line_cstate->buffering) > 0)
                        {
                            context_t *buf_ctx            = contextCreate(main_line);
                            buf_ctx->payload              = upload_line_cstate->buffering;
                            upload_line_cstate->buffering = NULL;
                            sbufShiftRight(buf_ctx->payload, sizeof(uint64_t));
                            self->up->upStream(self->up, buf_ctx);
                        }
                        else
                        {
                            bufferpoolResuesBuffer(contextGetBufferPool(c), upload_line_cstate->buffering);
                            upload_line_cstate->buffering = NULL;
                        }
                    }
                    else
                    {
                        mutexUnlock(&(state->upload_line_map_mutex));

                        cstate->state = kCsDownloadInTable;

                        mutexLock(&(state->download_line_map_mutex));
                        bool push_succeed = hmap_cons_t_insert(&(state->download_line_map), hash, cstate).inserted;
                        mutexUnlock(&(state->download_line_map_mutex));
                        if (! push_succeed)
                        {
                            LOGW("HalfDuplexServer: duplicate download connection closed");
                            CSTATE_DROP(c);
                            memoryFree(cstate);
                            self->dw->downStream(self->dw, contextCreateFinFrom(c));
                            contextDestroy(c);
                            return;
                        }

                        // tell upload line to re-check
                        struct notify_argument_s *evdata = memoryAllocate(sizeof(struct notify_argument_s));
                        *evdata = (struct notify_argument_s) {.self = self, .hash = hash, .tid = tid_upload_line};

                        wevent_t ev;
                        memorySet(&ev, 0, sizeof(ev));
                        ev.loop = getWorkerLoop(tid_upload_line);
                        ev.cb   = callNotifyDownloadLineIsReadyForBind;
                        weventSetUserData(&ev, evdata);
                        wloopPostEvent(getWorkerLoop(tid_upload_line), &ev);
                    }
                }
                else
                {
                    mutexUnlock(&(state->upload_line_map_mutex));
                    cstate->state = kCsDownloadInTable;

                    mutexLock(&(state->download_line_map_mutex));
                    bool push_succeed = hmap_cons_t_insert(&(state->download_line_map), hash, cstate).inserted;
                    mutexUnlock(&(state->download_line_map_mutex));
                    if (! push_succeed)
                    {
                        LOGW("HalfDuplexServer: duplicate download connection closed");
                        CSTATE_DROP(c);
                        memoryFree(cstate);
                        self->dw->downStream(self->dw, contextCreateFinFrom(c));
                        contextDestroy(c);
                        return;
                    }
                }
            }
            contextDestroy(c);

            break;
        }
        break;

        case kCsUploadInTable:
            if (cstate->buffering)
            {
                cstate->buffering = sbufAppendMerge(contextGetBufferPool(c), cstate->buffering, c->payload);
            }
            else
            {
                cstate->buffering = c->payload;
            }
            contextDropPayload(c);
            if (sbufGetBufLength(cstate->buffering) >= kMaxBuffering)
            {
                bufferpoolResuesBuffer(contextGetBufferPool(c), cstate->buffering);
                cstate->buffering = NULL;
            }
            contextDestroy(c);
            break;

        case kCsUploadDirect:
            self->up->upStream(self->up, contextSwitchLine(c, cstate->main_line));
            break;

        case kCsDownloadDirect:
        case kCsDownloadInTable:
            contextReusePayload(c);
            contextDestroy(c);
            break;
        }
    }
    else
    {
        if (c->init)
        {
            cstate  = memoryAllocate(sizeof(halfduplex_server_con_state_t));
            *cstate = (halfduplex_server_con_state_t) {
                .state = kCsUnkown, .buffering = NULL, .upload_line = NULL, .download_line = NULL};

            CSTATE_MUT(c) = cstate;
            if (isDownPiped(c->line))
            {
                // pipe dose not care
            }
            else
            {
                self->dw->downStream(self->dw, contextCreateEst(c->line));
            }
            contextDestroy(c);
        }
        else if (c->fin)
        {
            assert(cstate != NULL);

            switch (cstate->state)
            {

            case kCsUnkown:
                if (cstate->buffering)
                {
                    bufferpoolResuesBuffer(contextGetBufferPool(c), cstate->buffering);
                }
                CSTATE_DROP(c);
                memoryFree(cstate);
                contextDestroy(c);
                break;

            case kCsUploadInTable: {

                mutexLock(&(state->upload_line_map_mutex));

                hmap_cons_t_iter f_iter = hmap_cons_t_find(&(state->upload_line_map), cstate->hash);
                bool             found  = f_iter.ref != hmap_cons_t_end(&(state->upload_line_map)).ref;
                if (! found)
                {
                    LOGF("HalfDuplexServer: Thread safety is done incorrectly  [%s:%d]", __FILENAME__, __LINE__);
                    exit(1);
                }
                hmap_cons_t_erase_at(&(state->upload_line_map), f_iter);

                mutexUnlock(&(state->upload_line_map_mutex));
                bufferpoolResuesBuffer(contextGetBufferPool(c), cstate->buffering);
                CSTATE_DROP(c);
                memoryFree(cstate);
                contextDestroy(c);
            }
            break;

            case kCsDownloadInTable: {
                mutexLock(&(state->download_line_map_mutex));

                hmap_cons_t_iter f_iter = hmap_cons_t_find(&(state->download_line_map), cstate->hash);
                bool             found  = f_iter.ref != hmap_cons_t_end(&(state->download_line_map)).ref;
                if (! found)
                {
                    LOGF("HalfDuplexServer: Thread safety is done incorrectly  [%s:%d]", __FILENAME__, __LINE__);
                    exit(1);
                }
                hmap_cons_t_erase_at(&(state->download_line_map), f_iter);

                mutexUnlock(&(state->download_line_map_mutex));
                CSTATE_DROP(c);
                memoryFree(cstate);
                contextDestroy(c);
            }
            break;

            case kCsDownloadDirect: {
                doneLineUpSide(c->line);

                halfduplex_server_con_state_t *cstate_download = cstate;
                LSTATE_DROP(cstate_download->download_line);
                cstate_download->download_line = NULL;

                if (cstate_download->main_line)
                {
                    doneLineDownSide(cstate_download->main_line);
                    self->up->upStream(self->up, contextCreateFin(cstate_download->main_line));
                    lineDestroy(cstate_download->main_line);
                    cstate_download->main_line = NULL;
                }

                if (cstate_download->upload_line)
                {
                    doneLineUpSide(cstate_download->upload_line);

                    halfduplex_server_con_state_t *cstate_upload = LSTATE(cstate_download->upload_line);
                    LSTATE_DROP(cstate_download->upload_line);
                    cstate_upload->main_line     = NULL;
                    cstate_upload->download_line = NULL;
                    cstate_upload->upload_line   = NULL;

                    assert(cstate_upload->state == kCsUploadDirect);
                    if (isDownPiped(cstate_download->upload_line))
                    {
                        pipeDownStream(contextCreateFin(cstate_download->upload_line));
                    }
                    else
                    {
                        self->dw->downStream(self->dw, contextCreateFin(cstate_download->upload_line));
                    }
                    cstate_download->upload_line = NULL;
                    memoryFree(cstate_upload);
                }

                memoryFree(cstate_download);
                contextDestroy(c);
            }
            break;

            case kCsUploadDirect: {
                doneLineUpSide(c->line);

                halfduplex_server_con_state_t *cstate_upload = cstate;
                LSTATE_DROP(cstate_upload->upload_line);
                cstate_upload->upload_line = NULL;

                if (cstate_upload->main_line)
                {
                    doneLineDownSide(cstate_upload->main_line);
                    self->up->upStream(self->up, contextCreateFin(cstate_upload->main_line));
                    lineDestroy(cstate_upload->main_line);
                    cstate_upload->main_line = NULL;
                }

                if (cstate_upload->download_line)
                {
                    doneLineUpSide(cstate_upload->download_line);

                    halfduplex_server_con_state_t *cstate_download = LSTATE(cstate_upload->download_line);
                    LSTATE_MUT(cstate_upload->download_line)       = NULL;
                    cstate_download->main_line                     = NULL;
                    cstate_download->download_line                 = NULL;
                    cstate_download->upload_line                   = NULL;

                    self->dw->downStream(self->dw, contextCreateFin(cstate_upload->download_line));
                    cstate_upload->download_line = NULL;
                    memoryFree(cstate_download);
                }

                memoryFree(cstate_upload);
                contextDestroy(c);
            }
            break;

            default:
                LOGF("HalfDuplexServer: Unexpected  [%s:%d]", __FILENAME__, __LINE__);
                exit(1);
                break;
            }
        }
    }
}

static void downStream(tunnel_t *self, context_t *c)
{
    contextSwitchLine(c, ((halfduplex_server_con_state_t *) (c->line->dw_state))->download_line);
    halfduplex_server_con_state_t *cstate = CSTATE(c);
    if (c->payload != NULL)
    {
        switch (cstate->state)
        {
        case kCsDownloadDirect:
            self->dw->downStream(self->dw, c);
            break;

        case kCsUnkown:
        case kCsUploadInTable:
        case kCsDownloadInTable:
        case kCsUploadDirect:
        default:
            LOGF("HalfDuplexServer: Unexpected  [%s:%d]", __FILENAME__, __LINE__);
            exit(1);
            break;
        }
    }
    else
    {
        if (c->fin)
        {
            switch (cstate->state)
            {
            case kCsDownloadDirect:
                assert(cstate->upload_line);

                doneLineUpSide(cstate->upload_line);
                doneLineUpSide(cstate->download_line);
                doneLineDownSide(cstate->main_line);
                lineDestroy(cstate->main_line);

                halfduplex_server_con_state_t *upload_line_cstate = LSTATE(cstate->upload_line);
                upload_line_cstate->download_line                 = NULL;
                upload_line_cstate->main_line                     = NULL;

                LSTATE_MUT(cstate->download_line) = NULL;
                cstate->download_line             = NULL;
                cstate->main_line                 = NULL;

                self->dw->downStream(self->dw, contextCreateFin(c->line));

                upload_line_cstate = cstate->upload_line == NULL ? NULL : LSTATE(cstate->upload_line);
                if (upload_line_cstate)
                {
                    line_t *upload_line             = cstate->upload_line;
                    LSTATE_MUT(cstate->upload_line) = NULL;
                    upload_line_cstate->upload_line = NULL;
                    cstate->upload_line             = NULL;

                    assert(upload_line_cstate->state == kCsUploadDirect);

                    if (isDownPiped(upload_line))
                    {
                        pipeDownStream(contextCreateFin(upload_line));
                    }
                    else
                    {
                        self->dw->downStream(self->dw, contextCreateFin(upload_line));
                    }
                    memoryFree(upload_line_cstate);
                }

                memoryFree(cstate);
                contextDestroy(c);

                break;

            case kCsUnkown:
            case kCsUploadInTable:
            case kCsDownloadInTable:
            case kCsUploadDirect:
            default:
                LOGF("HalfDuplexServer: Unexpected  [%s:%d]", __FILENAME__, __LINE__);
                exit(1);
                break;
            }
        }
        else if (c->est)
        {
            contextDestroy(c);
        }
    }
}

tunnel_t *newHalfDuplexServer(node_instance_context_t *instance_info)
{
    (void) instance_info;

    halfduplex_server_state_t *state = memoryAllocate(sizeof(halfduplex_server_state_t));
    memorySet(state, 0, sizeof(halfduplex_server_state_t));

    mutexInit(&state->upload_line_map_mutex);
    mutexInit(&state->download_line_map_mutex);
    state->download_line_map = hmap_cons_t_with_capacity(kHmapCap);
    state->upload_line_map   = hmap_cons_t_with_capacity(kHmapCap);

    tunnel_t *t   = tunnelCreate();
    t->state      = state;
    t->upStream   = &upStream;
    t->downStream = &downStream;

    return t;
}

api_result_t apiHalfDuplexServer(tunnel_t *self, const char *msg)
{
    (void) (self);
    (void) (msg);
    return (api_result_t) {0};
}

tunnel_t *destroyHalfDuplexServer(tunnel_t *self)
{
    (void) (self);
    return NULL;
}

tunnel_metadata_t getMetadataHalfDuplexServer(void)
{
    return (tunnel_metadata_t) {.version = 0001, .flags = 0x0};
}
