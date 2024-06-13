#include "halfduplex_server.h"
#include "basic_types.h"
#include "buffer_pool.h"
#include "hmutex.h"
#include "loggers/network_logger.h"
#include "pipe_line.h"
#include "shiftbuffer.h"
#include "tunnel.h"
#include "ww.h"

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
    kCsUploadPipedIndirect,
    kCsUploadDirect,
    kCsUploadPipedDirect,
    kCsDownloadInTable,
    kCsDownloadDirect
};

typedef struct halfduplex_server_state_s
{
    hhybridmutex_t upload_line_map_mutex;
    hmap_cons_t    upload_line_map;

    hhybridmutex_t download_line_map_mutex;
    hmap_cons_t    download_line_map;

} halfduplex_server_state_t;

typedef struct halfduplex_server_con_state_s
{
    enum connection_status state;

    hash_t hash;

    shift_buffer_t *buffering;
    line_t         *upload_line;
    line_t         *download_line;
    line_t         *main_line;
    pipe_line_t    *pipe;
    bool            first_sent;

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
    if (cstate->pipe)
    {
        pipeOnUpLinePaused(cstate->pipe);
    }
    pauseLineDownSide(cstate->download_line);
}

static void onMainLineResumed(void *_cstate)
{
    halfduplex_server_con_state_t *cstate = _cstate;
    if (cstate->pipe)
    {
        pipeOnUpLineResumed(cstate->pipe);
    }
    resumeLineDownSide(cstate->download_line);
}

static void onDownloadLinePaused(void *_cstate)
{
    halfduplex_server_con_state_t *cstate = _cstate;
    if (cstate->main_line)
    {
        pauseLineUpSide(cstate->main_line);
    }
}

static void onDownloadLineResumed(void *_cstate)
{
    halfduplex_server_con_state_t *cstate = _cstate;
    if (cstate->main_line)
    {
        resumeLineDownSide(cstate->main_line);
    }
}

static void onUploadInDirectLinePaused(void *_cstate)
{
    halfduplex_server_con_state_t *cstate = _cstate;
    pipeOnDownLinePaused(cstate->pipe);
}

static void onUploadInDirectLineResumed(void *_cstate)
{
    halfduplex_server_con_state_t *cstate = _cstate;
    pipeOnDownLineResumed(cstate->pipe);
}

static void onUploadDirectLinePaused(void *_cstate)
{
    halfduplex_server_con_state_t *cstate = _cstate;
    pauseLineUpSide(cstate->main_line);
}

static void onUploadDirectLineResumed(void *_cstate)
{
    halfduplex_server_con_state_t *cstate = _cstate;
    assert(cstate->state != kCsDownloadDirect);
    resumeLineUpSide(cstate->main_line);
}

static void upStream(tunnel_t *self, context_t *c);

static void localUpStream(tunnel_t *self, context_t *c, pipe_line_t *pl)
{
    halfduplex_server_state_t     *state  = STATE(self);
    halfduplex_server_con_state_t *cstate = CSTATE(c);

    if (c->payload != NULL)
    {
        shift_buffer_t *buf = c->payload;

        if (c->first)
        {
            assert(bufLen(buf) >= sizeof(uint64_t));
            unsigned int blen = bufLen(buf);
            shiftr(c->payload, blen - sizeof(uint64_t));
            hash_t hash = 0x0;
            readUI64(c->payload, (uint64_t *) &hash);
            cstate->hash = hash;
            shiftl(c->payload, blen - sizeof(uint64_t));

            hhybridmutex_lock(&(state->download_line_map_mutex));
            hmap_cons_t_iter f_iter = hmap_cons_t_find(&(state->download_line_map), hash);
            bool             found  = f_iter.ref != hmap_cons_t_end(&(state->download_line_map)).ref;

            if (found)
            {
                // pair is found
                // since we are on the same thread, we can do cool stuff
                uint8_t tid_download_line = (*f_iter.ref).second->download_line->tid;

                if (tid_download_line != c->line->tid)
                {
                    LOGF("HalfDuplexServer: Unexpected  [%s:%d]", __FILENAME__, __LINE__);
                    exit(1);
                }
                line_t *download_line = ((halfduplex_server_con_state_t *) ((*f_iter.ref).second))->download_line;
                cstate->download_line = download_line;

                halfduplex_server_con_state_t *download_line_cstate =
                    ((halfduplex_server_con_state_t *) ((*f_iter.ref).second));

                hmap_cons_t_erase_at(&(state->download_line_map), f_iter);
                hhybridmutex_unlock(&(state->download_line_map_mutex));

                assert(download_line_cstate->state == kCsDownloadInTable);

                download_line_cstate->state       = kCsDownloadDirect;
                download_line_cstate->upload_line = c->line;
                setupLineUpSide(download_line, onDownloadLinePaused, download_line_cstate, onDownloadLineResumed);

                setupLineUpSide(c->line, onUploadDirectLinePaused, cstate, onUploadDirectLineResumed);
                line_t *main_line               = newLine(tid_download_line);
                download_line_cstate->main_line = main_line;
                cstate->main_line               = main_line;
                setupLineDownSide(main_line, onMainLinePaused, download_line_cstate, onMainLineResumed);
                lockLine(main_line);
                self->up->upStream(self->up, newInitContext(main_line));
                if (! isAlive(main_line))
                {
                    unLockLine(main_line);
                    reuseContextBuffer(c);
                    destroyContext(c);
                    return;
                }

                unLockLine(main_line);
                setLen(buf, blen - sizeof(uint64_t)); // dont need the hash part

                if (bufLen(buf) > 0)
                {
                    cstate->first_sent = true;
                    self->up->upStream(self->up, switchLine(c, main_line));
                }
                else
                {
                    reuseContextBuffer(c);
                    destroyContext(c);
                }
            }
            else
            {
                hhybridmutex_unlock(&(state->download_line_map_mutex));

                free(cstate);
                CSTATE_MUT(c)         = NULL;
                context_t *finish_ctx = newFinContextFrom(c);
                if (! pipeDownStream(pl, finish_ctx))
                {
                    destroyContext(finish_ctx);
                }
                reuseContextBuffer(c);
                destroyContext(c);
            }
        }
        else
        {
            if (! cstate->first_sent)
            {
                cstate->first_sent = true;
                c->first           = true;
            }
            self->up->upStream(self->up, switchLine(c, cstate->main_line));
        }
    }
    else
    {

        if ((c->init))
        {

            cstate  = malloc(sizeof(halfduplex_server_con_state_t));
            *cstate = (halfduplex_server_con_state_t){.state         = kCsUploadPipedDirect,
                                                      .buffering     = NULL,
                                                      .pipe          = pl,
                                                      .upload_line   = c->line,
                                                      .download_line = NULL,
                                                      .first_sent    = false};
            // pipe dose not need est
            CSTATE_MUT(c) = cstate;
            destroyContext(c);
        }
        else if (c->fin)
        {
            upStream(self, c);
        }
    }
}

static void localDownStream(tunnel_t *self, context_t *c, pipe_line_t *pl)
{
    (void) pl;
    halfduplex_server_con_state_t *cstate = CSTATE(c);

    if (WW_UNLIKELY(c->fin))
    {
        CSTATE_MUT(c) = NULL;
        free(cstate);
        self->dw->downStream(self->dw, c);
    }
    else
    {
        self->dw->downStream(self->dw, c);
    }
}

static void notifyDownloadLineIsReadyForBind(hash_t hash, tunnel_t *self, uint8_t this_tid)
{
    halfduplex_server_state_t *state = STATE(self);

    hhybridmutex_lock(&(state->upload_line_map_mutex));

    hmap_cons_t_iter f_iter = hmap_cons_t_find(&(state->upload_line_map), hash);
    bool             found  = f_iter.ref != hmap_cons_t_end(&(state->upload_line_map)).ref;

    if (found)
    {
        // upload pair is found
        uint8_t tid_upload_line = (*f_iter.ref).second->upload_line->tid;
        if (this_tid != tid_upload_line)
        {
            hhybridmutex_unlock(&(state->upload_line_map_mutex));

            return;
        }
        halfduplex_server_con_state_t *upload_line_cstate = ((halfduplex_server_con_state_t *) ((*f_iter.ref).second));

        hmap_cons_t_erase_at(&(state->upload_line_map), f_iter);
        hhybridmutex_unlock(&(state->upload_line_map_mutex));

        hhybridmutex_lock(&(state->download_line_map_mutex));
        f_iter = hmap_cons_t_find(&(state->download_line_map), hash);
        found  = f_iter.ref != hmap_cons_t_end(&(state->download_line_map)).ref;

        if (found)
        {
            // downlod pair is found
            uint8_t tid_download_line = (*f_iter.ref).second->download_line->tid;
            hhybridmutex_unlock(&(state->download_line_map_mutex));

            if (this_tid == tid_download_line || upload_line_cstate->state != kCsUploadInTable)
            {
                LOGF("HalfDuplexServer: Logic is incorrect.  [%s:%d]", __FILENAME__, __LINE__);
                exit(1);
            }
            atomic_thread_fence(memory_order_release);
            upload_line_cstate->state = kCsUploadPipedIndirect;

            newPipeLine(&upload_line_cstate->pipe, self, tid_upload_line, upload_line_cstate->upload_line,
                        tid_download_line, localUpStream, localDownStream);

            if (upload_line_cstate->buffering)
            {

                context_t *bctx               = newContext(upload_line_cstate->upload_line);
                bctx->payload                 = upload_line_cstate->buffering;
                upload_line_cstate->buffering = NULL;
                if (! pipeUpStream(upload_line_cstate->pipe, bctx))
                {
                    reuseContextBuffer(bctx);
                    destroyContext(bctx);
                }
            }
        }
        else
        {
            hhybridmutex_unlock(&(state->download_line_map_mutex));

            LSTATE_MUT(upload_line_cstate->upload_line) = NULL;
            self->dw->downStream(self->dw, newFinContext(upload_line_cstate->upload_line));
            free(upload_line_cstate);
        }
    }
    else
    {
        hhybridmutex_unlock(&(state->upload_line_map_mutex));

        // the connection just closed
    }
}

static void callNotifyDownloadLineIsReadyForBind(hevent_t *ev)
{
    struct notify_argument_s *args = hevent_userdata(ev);
    notifyDownloadLineIsReadyForBind(args->hash, args->self, args->tid);
    free(args);
}

static void upStream(tunnel_t *self, context_t *c)
{
    halfduplex_server_state_t     *state  = STATE(self);
    halfduplex_server_con_state_t *cstate = CSTATE(c);
    if (c->payload != NULL)
    {
        if (cstate == NULL)
        {
            reuseContextBuffer(c);
            destroyContext(c);
            return;
        }
        shift_buffer_t *buf = c->payload;

        switch (cstate->state)
        {

        case kCsUnkown: {

            if (cstate->buffering)
            {
                c->payload        = appendBufferMerge(getContextBufferPool(c), c->payload, cstate->buffering);
                cstate->buffering = NULL;
            }

            if (bufLen(buf) < sizeof(uint64_t))
            {
                cstate->buffering = c->payload;
                c->payload        = NULL;
                destroyContext(c);
                return;
            }
            unsigned int blen = bufLen(buf);
            shiftr(c->payload, blen - sizeof(uint64_t));
            const bool is_upload                   = (((uint8_t *) rawBuf(c->payload))[0] & 0x80) == 0x0;
            ((uint8_t *) rawBufMut(c->payload))[0] = (((uint8_t *) rawBuf(c->payload))[0] & 0x7F);

            hash_t hash = 0x0;
            readUI64(c->payload, (uint64_t *) &hash);
            cstate->hash = hash;
            shiftl(c->payload, blen - sizeof(uint64_t));

            if (is_upload)
            {
                cstate->upload_line = c->line;
                hhybridmutex_lock(&(state->download_line_map_mutex));
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
                        hhybridmutex_unlock(&(state->download_line_map_mutex));
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
                        lockLine(main_line);
                        self->up->upStream(self->up, newInitContext(main_line));

                        if (! isAlive(main_line))
                        {
                            unLockLine(main_line);
                            reuseContextBuffer(c);
                            destroyContext(c);
                            return;
                        }

                        unLockLine(main_line);

                        setLen(buf, blen - sizeof(uint64_t)); // dont need the hash part
                        if (bufLen(buf) > 0)
                        {
                            if (! cstate->first_sent)
                            {
                                cstate->first_sent = true;
                                c->first           = true;
                            }
                            self->up->upStream(self->up, switchLine(c, main_line));
                            return;
                        }
                        reuseContextBuffer(c);
                    }
                    else
                    {
                        hhybridmutex_unlock(&(state->download_line_map_mutex));
                        cstate->state = kCsUploadPipedIndirect;
                        setupLineUpSide(c->line, onUploadInDirectLinePaused, cstate, onUploadInDirectLineResumed);

                        newPipeLine(&cstate->pipe, self, c->line->tid, c->line, tid_download_line, localUpStream,
                                    localDownStream);

                        if (! pipeUpStream(cstate->pipe, c))
                        {
                            reuseContextBuffer(c);
                            destroyContext(c);
                        }
                        return;
                    }
                }
                else
                {
                    hhybridmutex_unlock(&(state->download_line_map_mutex));
                    cstate->state = kCsUploadInTable;

                    hhybridmutex_lock(&(state->upload_line_map_mutex));
                    bool push_succeed = hmap_cons_t_insert(&(state->upload_line_map), hash, cstate).inserted;
                    hhybridmutex_unlock(&(state->upload_line_map_mutex));

                    if (! push_succeed)
                    {
                        LOGW("HalfDuplexServer: duplicate upload connection closed");
                        reuseContextBuffer(c);
                        free(cstate);
                        CSTATE_MUT(c) = NULL;
                        self->dw->downStream(self->dw, newFinContextFrom(c));
                        destroyContext(c);
                        return;
                    }

                    if (bufLen(buf) > 0)
                    {
                        cstate->buffering = buf;
                        c->payload        = NULL;
                    }
                    else
                    {
                        reuseContextBuffer(c);
                    }
                    // upload connection is waiting in the pool
                }
            }
            else
            {
                reuseContextBuffer(c);
                cstate->download_line = c->line;

                hhybridmutex_lock(&(state->upload_line_map_mutex));
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
                        hhybridmutex_unlock(&(state->upload_line_map_mutex));
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
                        lockLine(main_line);
                        self->up->upStream(self->up, newInitContext(main_line));

                        if (! isAlive(main_line))
                        {
                            unLockLine(main_line);
                            destroyContext(c);
                            return;
                        }
                        unLockLine(main_line);

                        assert(upload_line_cstate->buffering);

                        setLen(upload_line_cstate->buffering,
                               bufLen(upload_line_cstate->buffering) - sizeof(uint64_t)); // dont need the hash part
                        if (bufLen(upload_line_cstate->buffering) > 0)
                        {
                            context_t *buf_ctx             = newContext(main_line);
                            buf_ctx->payload               = upload_line_cstate->buffering;
                            buf_ctx->first                 = true;
                            upload_line_cstate->buffering  = NULL;
                            upload_line_cstate->first_sent = true;
                            self->up->upStream(self->up, buf_ctx);
                        }
                        else
                        {
                            reuseBuffer(getContextBufferPool(c), upload_line_cstate->buffering);
                            upload_line_cstate->buffering = NULL;
                        }
                    }
                    else
                    {
                        hhybridmutex_unlock(&(state->upload_line_map_mutex));

                        cstate->state = kCsDownloadInTable;

                        hhybridmutex_lock(&(state->download_line_map_mutex));
                        bool push_succeed = hmap_cons_t_insert(&(state->download_line_map), hash, cstate).inserted;
                        hhybridmutex_unlock(&(state->download_line_map_mutex));
                        if (! push_succeed)
                        {
                            LOGW("HalfDuplexServer: duplicate download connection closed");
                            free(cstate);
                            CSTATE_MUT(c) = NULL;
                            self->dw->downStream(self->dw, newFinContextFrom(c));
                            destroyContext(c);
                            return;
                        }

                        // tell upload line to re-check
                        struct notify_argument_s *evdata = malloc(sizeof(struct notify_argument_s));
                        *evdata = (struct notify_argument_s){.self = self, .hash = hash, .tid = tid_upload_line};

                        hevent_t ev;
                        memset(&ev, 0, sizeof(ev));
                        ev.loop = loops[tid_upload_line];
                        ev.cb   = callNotifyDownloadLineIsReadyForBind;
                        hevent_set_userdata(&ev, evdata);
                        hloop_post_event(loops[tid_upload_line], &ev);
                    }
                }
                else
                {
                    hhybridmutex_unlock(&(state->upload_line_map_mutex));
                    cstate->state = kCsDownloadInTable;

                    hhybridmutex_lock(&(state->download_line_map_mutex));
                    bool push_succeed = hmap_cons_t_insert(&(state->download_line_map), hash, cstate).inserted;
                    hhybridmutex_unlock(&(state->download_line_map_mutex));
                    if (! push_succeed)
                    {
                        LOGW("HalfDuplexServer: duplicate download connection closed");
                        free(cstate);
                        CSTATE_MUT(c) = NULL;
                        self->dw->downStream(self->dw, newFinContextFrom(c));
                        destroyContext(c);
                        return;
                    }
                }
            }
            destroyContext(c);

            break;
        }
        break;

        case kCsUploadInTable:
            if (cstate->buffering)
            {
                cstate->buffering = appendBufferMerge(getContextBufferPool(c), cstate->buffering, c->payload);
            }
            else
            {
                cstate->buffering = c->payload;
            }
            c->payload = NULL;
            if (bufLen(cstate->buffering) >= kMaxBuffering)
            {
                reuseBuffer(getContextBufferPool(c), cstate->buffering);
                cstate->buffering = NULL;
            }
            destroyContext(c);
            break;

        case kCsUploadPipedIndirect:
            if (! pipeUpStream(cstate->pipe, c))
            {
                reuseContextBuffer(c);
                destroyContext(c);
            }
            break;

        case kCsUploadPipedDirect:
        case kCsUploadDirect:
            if (! cstate->first_sent)
            {
                cstate->first_sent = true;
                c->first           = true;
            }
            self->up->upStream(self->up, switchLine(c, cstate->main_line));
            break;

        case kCsDownloadDirect:
        case kCsDownloadInTable:
            reuseContextBuffer(c);
            destroyContext(c);
            break;
        }
    }
    else
    {
        if (c->init)
        {
            cstate  = malloc(sizeof(halfduplex_server_con_state_t));
            *cstate = (halfduplex_server_con_state_t){.state         = kCsUnkown,
                                                      .buffering     = NULL,
                                                      .pipe          = NULL,
                                                      .upload_line   = NULL,
                                                      .download_line = NULL,
                                                      .first_sent    = false};

            CSTATE_MUT(c) = cstate;
            self->dw->downStream(self->dw, newEstContext(c->line));
            destroyContext(c);
        }
        else if (c->fin)
        {
            if (cstate == NULL)
            {
                destroyContext(c);
                return;
            }
            switch (cstate->state)
            {

            case kCsUnkown:
                if (cstate->buffering)
                {
                    reuseBuffer(getContextBufferPool(c), cstate->buffering);
                }
                free(cstate);
                CSTATE_MUT(c) = NULL;
                destroyContext(c);
                break;

            case kCsUploadInTable: {

                hhybridmutex_lock(&(state->upload_line_map_mutex));

                hmap_cons_t_iter f_iter = hmap_cons_t_find(&(state->upload_line_map), cstate->hash);
                bool             found  = f_iter.ref != hmap_cons_t_end(&(state->upload_line_map)).ref;
                if (! found)
                {
                    LOGF("HalfDuplexServer: Thread safety is done incorrectly  [%s:%d]", __FILENAME__, __LINE__);
                    exit(1);
                }
                hmap_cons_t_erase_at(&(state->upload_line_map), f_iter);

                hhybridmutex_unlock(&(state->upload_line_map_mutex));
                reuseBuffer(getContextBufferPool(c), cstate->buffering);
                free(cstate);
                CSTATE_MUT(c) = NULL;
                destroyContext(c);
            }
            break;

            case kCsDownloadInTable: {
                hhybridmutex_lock(&(state->download_line_map_mutex));

                hmap_cons_t_iter f_iter = hmap_cons_t_find(&(state->download_line_map), cstate->hash);
                bool             found  = f_iter.ref != hmap_cons_t_end(&(state->download_line_map)).ref;
                if (! found)
                {
                    LOGF("HalfDuplexServer: Thread safety is done incorrectly  [%s:%d]", __FILENAME__, __LINE__);
                    exit(1);
                }
                hmap_cons_t_erase_at(&(state->download_line_map), f_iter);

                hhybridmutex_unlock(&(state->download_line_map_mutex));
                free(cstate);
                CSTATE_MUT(c) = NULL;
                destroyContext(c);
            }
            break;

            case kCsDownloadDirect: {
                doneLineUpSide(c->line);

                halfduplex_server_con_state_t *cstate_download = cstate;
                LSTATE_MUT(cstate_download->download_line)     = NULL;
                cstate_download->download_line                 = NULL;

                if (cstate_download->main_line)
                {
                    doneLineDownSide(cstate_download->main_line);
                    self->up->upStream(self->up, newFinContext(cstate_download->main_line));
                    destroyLine(cstate_download->main_line);
                    cstate_download->main_line = NULL;
                }

                if (cstate_download->upload_line)
                {
                    doneLineUpSide(cstate_download->upload_line);

                    halfduplex_server_con_state_t *cstate_upload = LSTATE(cstate_download->upload_line);
                    LSTATE_MUT(cstate_download->upload_line)     = NULL;
                    cstate_upload->main_line                     = NULL;
                    cstate_upload->download_line                 = NULL;
                    cstate_upload->upload_line                   = NULL;

                    if (cstate_upload->state == kCsUploadDirect)
                    {
                        self->dw->downStream(self->dw, newFinContext(cstate_download->upload_line));
                    }
                    else if (cstate_upload->state == kCsUploadPipedDirect)
                    {
                        context_t *finish_ctx = newFinContext(cstate_download->upload_line);
                        if (! pipeDownStream(cstate_upload->pipe, finish_ctx))
                        {
                            destroyContext(finish_ctx);
                        }
                    }
                    else
                    {
                        LOGF("HalfDuplexServer: Unexpected  [%s:%d]", __FILENAME__, __LINE__);
                        exit(1);
                    }
                    cstate_download->upload_line = NULL;
                    free(cstate_upload);
                }

                free(cstate_download);
                destroyContext(c);
            }
            break;

            case kCsUploadPipedDirect:
            case kCsUploadDirect: {
                doneLineUpSide(c->line);

                halfduplex_server_con_state_t *cstate_upload = cstate;
                LSTATE_MUT(cstate_upload->upload_line)       = NULL;
                cstate_upload->upload_line                   = NULL;

                if (cstate_upload->main_line)
                {
                    doneLineDownSide(cstate_upload->main_line);
                    self->up->upStream(self->up, newFinContext(cstate_upload->main_line));
                    destroyLine(cstate_upload->main_line);
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

                    self->dw->downStream(self->dw, newFinContext(cstate_upload->download_line));
                    cstate_upload->download_line = NULL;
                    free(cstate_download);
                }

                free(cstate_upload);
                destroyContext(c);
            }
            break;

            case kCsUploadPipedIndirect: {
                halfduplex_server_con_state_t *upload_line_cstate = LSTATE(cstate->upload_line);

                CSTATE_MUT(c) = NULL;
                doneLineUpSide(c->line);
                if (! pipeUpStream(upload_line_cstate->pipe, c))
                {
                    destroyContext(c);
                }
                free(upload_line_cstate);
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

    switchLine(c, ((halfduplex_server_con_state_t *) (c->line->dw_state))->download_line);
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
        case kCsUploadPipedIndirect:
        case kCsUploadPipedDirect:
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
                destroyLine(cstate->main_line);

                halfduplex_server_con_state_t *upload_line_cstate = LSTATE(cstate->upload_line);
                upload_line_cstate->download_line                 = NULL;
                upload_line_cstate->main_line                     = NULL;

                LSTATE_MUT(cstate->download_line) = NULL;
                cstate->download_line             = NULL;
                cstate->main_line                 = NULL;

                self->dw->downStream(self->dw, newFinContext(c->line));

                upload_line_cstate = LSTATE(cstate->upload_line);
                if (upload_line_cstate)
                {
                    line_t *upload_line             = cstate->upload_line;
                    LSTATE_MUT(cstate->upload_line) = NULL;
                    upload_line_cstate->upload_line = NULL;
                    cstate->upload_line             = NULL;

                    if (upload_line_cstate->state == kCsUploadDirect)
                    {
                        self->dw->downStream(self->dw, newFinContext(upload_line));
                        free(upload_line_cstate);
                    }
                    else if (upload_line_cstate->state == kCsUploadPipedDirect)
                    {
                        context_t *finish_ctx = newFinContext(upload_line);
                        if (! pipeDownStream(upload_line_cstate->pipe, finish_ctx))
                        {
                            destroyContext(finish_ctx);
                        }
                        free(upload_line_cstate);
                    }
                    else
                    {
                        LOGF("HalfDuplexServer: Unexpected  [%s:%d]", __FILENAME__, __LINE__);
                        exit(1);
                    }
                }

                free(cstate);
                destroyContext(c);

                break;

            case kCsUnkown:
            case kCsUploadInTable:
            case kCsDownloadInTable:
            case kCsUploadPipedIndirect:
            case kCsUploadDirect:
            case kCsUploadPipedDirect:
            default:
                LOGF("HalfDuplexServer: Unexpected  [%s:%d]", __FILENAME__, __LINE__);
                exit(1);
                break;
            }
        }
        else if (c->est)
        {
            destroyContext(c);
        }
    }
}

tunnel_t *newHalfDuplexServer(node_instance_context_t *instance_info)
{
    (void) instance_info;

    halfduplex_server_state_t *state = malloc(sizeof(halfduplex_server_state_t));
    memset(state, 0, sizeof(halfduplex_server_state_t));

    hhybridmutex_init(&state->upload_line_map_mutex);
    hhybridmutex_init(&state->download_line_map_mutex);
    state->download_line_map = hmap_cons_t_with_capacity(kHmapCap);
    state->upload_line_map   = hmap_cons_t_with_capacity(kHmapCap);

    tunnel_t *t   = newTunnel();
    t->state      = state;
    t->upStream   = &upStream;
    t->downStream = &downStream;

    return t;
}

api_result_t apiHalfDuplexServer(tunnel_t *self, const char *msg)
{
    (void) (self);
    (void) (msg);
    return (api_result_t){0};
}

tunnel_t *destroyHalfDuplexServer(tunnel_t *self)
{
    (void) (self);
    return NULL;
}
tunnel_metadata_t getMetadataHalfDuplexServer(void)
{
    return (tunnel_metadata_t){.version = 0001, .flags = 0x0};
}
