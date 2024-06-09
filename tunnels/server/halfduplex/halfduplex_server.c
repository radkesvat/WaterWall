#include "halfduplex_server.h"
#include "basic_types.h"
#include "buffer_pool.h"
#include "herr.h"
#include "hmutex.h"
#include "loggers/network_logger.h"
#include "pipe_line.h"
#include "shiftbuffer.h"
#include "tunnel.h"
#include "ww.h"
#include <stdbool.h>
#include <stdint.h>

#define i_type hmap_cons_t                            // NOLINT
#define i_key  hash_t                                 // NOLINT
#define i_val  struct halfduplex_server_con_state_s * // NOLINT

enum
{
    kHmapCap = 16 * 4
};

#include "stc/hmap.h"

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
    pipe_line_t    *pipe;
    bool            first_sent;

} halfduplex_server_con_state_t;

struct notify_argument_s
{
    tunnel_t *self;
    hash_t    hash;
    uint8_t   tid;
};

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
            hash_t hash = 0x0;
            readUI64(c->payload, (uint64_t *) &hash);
            hash         = hash & (0x7FFFFFFFFFFFFFFFULL);
            cstate->hash = hash;
            shiftr(buf, sizeof(uint64_t));

            hhybridmutex_lock(&(state->download_line_map_mutex));
            hmap_cons_t_iter f_iter = hmap_cons_t_find(&(state->download_line_map), hash);
            bool             found  = f_iter.ref == hmap_cons_t_end(&(state->download_line_map)).ref;

            if (found)
            {
                hhybridmutex_unlock(&(state->download_line_map_mutex));

                // pair is found
                // since we are on the same thread, we can do cool stuff

                uint8_t tid_download_line = (*f_iter.ref).second->download_line->tid;

                assert(tid_download_line == c->line->tid);
                hmap_cons_t_erase_at(&(state->download_line_map), f_iter);
                hhybridmutex_unlock(&(state->download_line_map_mutex));

                line_t *download_line = ((halfduplex_server_con_state_t *) ((*f_iter.ref).second))->download_line;
                cstate->download_line = download_line;

                halfduplex_server_con_state_t *download_line_cstate =
                    ((halfduplex_server_con_state_t *) ((*f_iter.ref).second));

                assert(download_line_cstate->state == kCsDownloadInTable);

                download_line_cstate->state       = kCsDownloadDirect;
                download_line_cstate->upload_line = c->line;

                lockLine(download_line);
                context_t *i_ctx = newInitContext(download_line);
                self->up->upStream(self->up, i_ctx);

                if (! isAlive(download_line))
                {
                    unLockLine(download_line);
                    reuseContextBuffer(c);
                    destroyContext(c);
                    return;
                }

                unLockLine(download_line);

                if (bufLen(buf) > 0)
                {
                    cstate->first_sent = true;
                    self->up->upStream(self->up, switchLine(c, download_line));
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
                CSTATE_MUT(c) = NULL;
                pipeDownStream(pl, newFinContextFrom(c));
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
            self->up->upStream(self->up, switchLine(c, cstate->download_line));
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

            CSTATE_MUT(c) = cstate;
        }
        else
        {
            destroyContext(c);
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
        self->dw->downStream(self->dw, c);
        free(cstate);
    }
    else if (WW_UNLIKELY(c->est))
    {
        destroyContext(c);
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
    bool             found  = f_iter.ref == hmap_cons_t_end(&(state->upload_line_map)).ref;

    if (found)
    {
        // upload pair is found
        hmap_cons_t_erase_at(&(state->upload_line_map), f_iter);
        uint8_t tid_upload_line = (*f_iter.ref).second->upload_line->tid;
        hhybridmutex_unlock(&(state->upload_line_map_mutex));

        if (this_tid != tid_upload_line)
        {
            return;
        }

        halfduplex_server_con_state_t *upload_line_cstate = ((halfduplex_server_con_state_t *) ((*f_iter.ref).second));

        hhybridmutex_lock(&(state->download_line_map_mutex));
        f_iter = hmap_cons_t_find(&(state->download_line_map), hash);
        found  = f_iter.ref == hmap_cons_t_end(&(state->download_line_map)).ref;

        if (found)
        {
            // downlod pair is found
            uint8_t tid_download_line = (*f_iter.ref).second->download_line->tid;
            hhybridmutex_unlock(&(state->download_line_map_mutex));

            if (this_tid == tid_download_line || upload_line_cstate->state != kCsUploadPipedIndirect)
            {
                LOGF("HalfDuplexServer: Logic is incorrect.  [%s:%d]", __FILENAME__, __LINE__);
                exit(1);
            }

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

        shift_buffer_t *buf = c->payload;

        switch (cstate->state)
        {

        case kCsUnkown: {
            // todo (buffering) do the buffering
            if (cstate->buffering)
            {
                c->payload        = appendBufferMerge(getContextBufferPool(c), c->payload, cstate->buffering);
                cstate->buffering = NULL;
            }

            if (bufLen(buf) < 8)
            {
                cstate->buffering = c->payload;
                c->payload        = NULL;
                destroyContext(c);
                return;
            }
            const bool is_upload = (((uint8_t *) rawBuf(c->payload))[0] & 0x80) == 0x0;

            hash_t hash = 0x0;
            readUI64(c->payload, (uint64_t *) &hash);
            hash         = hash & (0x7FFFFFFFFFFFFFFFULL);
            cstate->hash = hash;
            shiftr(buf, sizeof(uint64_t));

            if (is_upload)
            {
                cstate->upload_line = c->line;
                hhybridmutex_lock(&(state->download_line_map_mutex));
                hmap_cons_t_iter f_iter = hmap_cons_t_find(&(state->download_line_map), hash);
                bool             found  = f_iter.ref == hmap_cons_t_end(&(state->download_line_map)).ref;

                if (found)
                {
                    // pair is found
                    uint8_t tid_download_line = (*f_iter.ref).second->download_line->tid;

                    if (tid_download_line == c->line->tid)
                    {
                        hmap_cons_t_erase_at(&(state->download_line_map), f_iter);
                        hhybridmutex_unlock(&(state->download_line_map_mutex));
                        cstate->state = kCsUploadDirect;

                        line_t *download_line =
                            ((halfduplex_server_con_state_t *) ((*f_iter.ref).second))->download_line;

                        halfduplex_server_con_state_t *download_line_cstate =
                            ((halfduplex_server_con_state_t *) ((*f_iter.ref).second));

                        assert(download_line_cstate->state == kCsDownloadInTable);

                        download_line_cstate->state       = kCsDownloadDirect;
                        download_line_cstate->upload_line = c->line;

                        lockLine(download_line);
                        context_t *i_ctx = newInitContext(download_line);
                        self->up->upStream(self->up, i_ctx);

                        if (! isAlive(download_line))
                        {
                            unLockLine(download_line);
                            reuseContextBuffer(c);
                            destroyContext(c);
                            return;
                        }

                        unLockLine(download_line);

                        if (bufLen(buf) > 0)
                        {
                            if (! cstate->first_sent)
                            {
                                cstate->first_sent = true;
                                c->first           = true;
                            }
                            self->up->upStream(self->up, switchLine(c, download_line));
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
                        cstate->state = kCsUploadPipedIndirect;

                        newPipeLine(&cstate->pipe, self, c->line->tid, c->line, tid_download_line, localUpStream,
                                    localDownStream);

                        shiftl(buf, sizeof(uint64_t));
                        pipeUpStream(cstate->pipe, c);
                    }
                }
                else
                {
                    hhybridmutex_unlock(&(state->download_line_map_mutex));

                    hhybridmutex_lock(&(state->upload_line_map_mutex));
                    bool push_succeed = hmap_cons_t_push(&(state->upload_line_map), (hmap_cons_t_value){hash, cstate});
                    hhybridmutex_unlock(&(state->upload_line_map_mutex));

                    if (! push_succeed)
                    {
                        LOGW("HalfDuplexServer: duplicate upload connection closed");
                        reuseContextBuffer(c);
                        free(cstate);
                        CSTATE_MUT(c) = NULL;
                        self->dw->downStream(self->dw, newFinContextFrom(c)); //
                        destroyContext(c);
                        return;
                    }
                    cstate->state = kCsUploadInTable;

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
                bool             found  = f_iter.ref == hmap_cons_t_end(&(state->upload_line_map)).ref;

                if (found)
                {
                    // pair is found
                    uint8_t tid_upload_line = (*f_iter.ref).second->upload_line->tid;

                    if (tid_upload_line == c->line->tid)
                    {
                        hmap_cons_t_erase_at(&(state->upload_line_map), f_iter);
                        hhybridmutex_unlock(&(state->upload_line_map_mutex));
                        cstate->state = kCsDownloadDirect;

                        halfduplex_server_con_state_t *upload_line_cstate =
                            ((halfduplex_server_con_state_t *) ((*f_iter.ref).second));

                        assert(upload_line_cstate->state == kCsUploadInTable);

                        upload_line_cstate->state         = kCsUploadDirect;
                        upload_line_cstate->download_line = c->line;

                        self->up->upStream(self->up, newInitContext(c->line));

                        if (! isAlive(c->line))
                        {
                            destroyContext(c);
                            return;
                        }
                        if (upload_line_cstate->buffering)
                        {
                            context_t *buf_ctx             = newContextFrom(c);
                            buf_ctx->payload               = upload_line_cstate->buffering;
                            upload_line_cstate->buffering  = NULL;
                            upload_line_cstate->first_sent = true;
                            self->up->upStream(self->up, buf_ctx);
                        }
                    }
                    else
                    {
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

                    hhybridmutex_lock(&(state->download_line_map_mutex));
                    bool push_succeed =
                        hmap_cons_t_push(&(state->download_line_map), (hmap_cons_t_value){hash, cstate});
                    hhybridmutex_unlock(&(state->download_line_map_mutex));
                    if (! push_succeed)
                    {
                        LOGW("HalfDuplexServer: duplicate upload connection closed");
                        free(cstate);
                        CSTATE_MUT(c) = NULL;
                        self->dw->downStream(self->dw, newFinContextFrom(c)); //
                        destroyContext(c);
                        return;
                    }
                    cstate->state = kCsDownloadInTable;

                    destroyContext(c);
                }
            }

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
            destroyContext(c);
            break;

        case kCsUploadPipedIndirect:
            if (! pipeUpStream(cstate->pipe, c))
            {
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
            self->up->upStream(self->up, c);
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
            switch (cstate->state)
            {

            case kCsUnkown:

                free(cstate);
                CSTATE_MUT(c) = NULL;
                destroyContext(c);
                break;

            case kCsUploadInTable: {
                hhybridmutex_lock(&(state->upload_line_map_mutex));

                hmap_cons_t_iter f_iter = hmap_cons_t_find(&(state->upload_line_map), cstate->hash);
                bool             found  = f_iter.ref == hmap_cons_t_end(&(state->upload_line_map)).ref;
                if (! found)
                {
                    LOGF("HalfDuplexServer: Thread safety is done incorrectly  [%s:%d]", __FILENAME__, __LINE__);
                    exit(1);
                }
                hmap_cons_t_erase_at(&(state->upload_line_map), f_iter);

                hhybridmutex_unlock(&(state->upload_line_map_mutex));

                free(cstate);
                CSTATE_MUT(c) = NULL;
                destroyContext(c);
            }
            break;

            case kCsDownloadInTable: {
                hhybridmutex_lock(&(state->download_line_map_mutex));

                hmap_cons_t_iter f_iter = hmap_cons_t_find(&(state->download_line_map), cstate->hash);
                bool             found  = f_iter.ref == hmap_cons_t_end(&(state->download_line_map)).ref;
                if (! found)
                {
                    LOGF("HalfDuplexServer: Thread safety is done incorrectly  [%s:%d]", __FILENAME__, __LINE__);
                    exit(1);
                }
                hmap_cons_t_erase_at(&(state->upload_line_map), f_iter);

                hhybridmutex_unlock(&(state->download_line_map_mutex));

                free(cstate);
                CSTATE_MUT(c) = NULL;
                destroyContext(c);
            }
            break;

            case kCsDownloadDirect: {
                halfduplex_server_con_state_t *cstate_upload   = LSTATE(cstate->upload_line);
                halfduplex_server_con_state_t *cstate_download = LSTATE(cstate->download_line);

                LSTATE_MUT(cstate->upload_line) = NULL;
                if (cstate_upload->pipe)
                {
                    context_t *fctx = newFinContext(cstate_upload->upload_line);

                    if (! pipeDownStream(cstate_upload->pipe, fctx))
                    {
                        destroyContext(fctx);
                    }
                }
                else
                {
                    self->dw->downStream(self->dw, newFinContext(cstate_upload->upload_line));
                }
                free(cstate_upload);
                free(cstate_download);

                CSTATE_MUT(c) = NULL;
                self->up->upStream(self->up, c);
            }
            break;

            case kCsUploadPipedDirect:
            case kCsUploadDirect: {
                halfduplex_server_con_state_t *cstate_upload   = LSTATE(cstate->upload_line);
                halfduplex_server_con_state_t *cstate_download = LSTATE(cstate->download_line);

                CSTATE_MUT(c)                     = NULL;
                LSTATE_MUT(cstate->download_line) = NULL;

                self->up->upStream(self->up, newFinContext(cstate_download->download_line));
                self->dw->downStream(self->dw, newFinContext(cstate_upload->download_line));
                free(cstate_upload);
                free(cstate_download);

                destroyContext(c);
            }
            break;

            case kCsUploadPipedIndirect: {
                halfduplex_server_con_state_t *cstate_upload = LSTATE(cstate->upload_line);
                CSTATE_MUT(c)                                = NULL;

                if (! pipeUpStream(cstate_upload->pipe, c))
                {
                    destroyContext(c);
                }
                free(cstate_upload);
            }
            break;
            }
        }
    }
}

static void downStream(tunnel_t *self, context_t *c)
{
    halfduplex_server_con_state_t *cstate = CSTATE(c);
    if (c->payload != NULL)
    {
        switch (cstate->state)
        {
        case kCsUnkown:
        case kCsUploadInTable:
        case kCsDownloadInTable:
        case kCsUploadPipedIndirect:
        case kCsUploadPipedDirect:
        case kCsUploadDirect:
            LOGF("HalfDuplexServer: Unexpected  [%s:%d]", __FILENAME__, __LINE__);
            exit(1);
            break;

        case kCsDownloadDirect:
            self->dw->downStream(self->dw, c);
            break;
        }
    }
    else
    {
        if (c->fin)
        {
            CSTATE_MUT(c) = NULL;
            switch (cstate->state)
            {

            case kCsUnkown:
            case kCsUploadInTable:
            case kCsDownloadInTable:
            case kCsUploadPipedIndirect:
            case kCsUploadDirect:
            case kCsUploadPipedDirect:
                LOGF("HalfDuplexServer: Unexpected  [%s:%d]", __FILENAME__, __LINE__);
                exit(1);
                break;

            case kCsDownloadDirect:
                assert(cstate->upload_line);
                halfduplex_server_con_state_t *upload_line_cstate = LSTATE(cstate->upload_line);
                LSTATE_MUT(cstate->upload_line)                   = NULL;

                if (upload_line_cstate->state == kCsUploadDirect)
                {
                    self->dw->downStream(self->dw, newFinContext(cstate->upload_line));
                    free(upload_line_cstate);
                }
                else if (upload_line_cstate->state == kCsUploadPipedIndirect)
                {
                    pipeDownStream(upload_line_cstate->pipe, newFinContext(cstate->upload_line));
                    free(upload_line_cstate);
                }
                else
                {
                    LOGF("HalfDuplexServer: Unexpected  [%s:%d]", __FILENAME__, __LINE__);
                    exit(1);
                }
                free(cstate);
                self->dw->downStream(self->dw, c);
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
