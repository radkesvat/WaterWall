#include "halfduplex_client.h"
#include "buffer_pool.h"
#include "frand.h"
#include "shiftbuffer.h"
#include "tunnel.h"

typedef struct halfduplex_state_s
{
    void *_;
} halfduplex_state_t;

typedef struct halfduplex_con_state_s
{
    line_t *main_line;
    line_t *upload_line;
    line_t *download_line;
    bool    first_packet_sent;
} halfduplex_con_state_t;

static void onMainLinePaused(void *cstate)
{
    // pauseLineUpSide(((halfduplex_con_state_t *) cstate)->upload_line);
    pauseLineUpSide(((halfduplex_con_state_t *) cstate)->download_line);
}

static void onMainLineResumed(void *cstate)
{
    resumeLineUpSide(((halfduplex_con_state_t *) cstate)->upload_line);
    resumeLineUpSide(((halfduplex_con_state_t *) cstate)->download_line);
}
static void onUDLinePaused(void *cstate)
{
    pauseLineDownSide(((halfduplex_con_state_t *) cstate)->main_line);
}

static void onUDLineResumed(void *cstate)
{
    resumeLineDownSide(((halfduplex_con_state_t *) cstate)->main_line);
    resumeLineUpSide(((halfduplex_con_state_t *) cstate)->download_line);
    resumeLineUpSide(((halfduplex_con_state_t *) cstate)->upload_line);
}

static void upStream(tunnel_t *self, context_t *c)
{
    halfduplex_con_state_t *cstate = CSTATE(c);

    if (c->payload != NULL)
    {
        if (!cstate->first_packet_sent)
        {
            cstate->first_packet_sent = true;
            // 63 bits of random is enough and is better than hashing sender addr on halfduplex server, i believe so...
            uint32_t cids[2]   = {fastRand(), fastRand()};
            uint8_t *cid_bytes = (uint8_t *) &(cids[0]);

            context_t *intro_context = newContext(cstate->download_line);
            intro_context->payload   = popBuffer(getContextBufferPool(c));

            cid_bytes[0] = cid_bytes[0] | (1 << 7); // kHLFDCmdDownload
            shiftl(intro_context->payload, sizeof(cids));
            writeRaw(intro_context->payload, cid_bytes, sizeof(cids));

            self->up->upStream(self->up, intro_context);

            if (! isAlive(c->line))
            {
                reuseContextPayload(c);
                destroyContext(c);
                return;
            }

            cid_bytes[0] = cid_bytes[0] & 0x7f; // kHLFDCmdUpload
            shiftl(c->payload, 8);
            writeRaw(c->payload, cid_bytes, sizeof(cids));
        }
        self->up->upStream(self->up, switchLine(c, cstate->upload_line));
    }
    else
    {

        if (c->init)
        {
            cstate = wwmGlobalMalloc(sizeof(halfduplex_con_state_t));

            *cstate = (halfduplex_con_state_t) {.download_line = NULL, .upload_line = NULL, .main_line = c->line};

            LSTATE_MUT(cstate->main_line) = cstate;

            cstate->upload_line             = newLine(c->line->tid);
            LSTATE_MUT(cstate->upload_line) = cstate;
            lockLine(cstate->upload_line);
            self->up->upStream(self->up, newInitContext(cstate->upload_line));
            if (! isAlive(cstate->upload_line))
            {
                unLockLine(cstate->upload_line);
                destroyContext(c);
                return;
            }
            unLockLine(cstate->upload_line);

            cstate->download_line             = newLine(c->line->tid);
            LSTATE_MUT(cstate->download_line) = cstate;
            lockLine(cstate->download_line);
            self->up->upStream(self->up, newInitContext(cstate->download_line));

            if (! isAlive(cstate->download_line))
            {
                unLockLine(cstate->download_line);
                destroyContext(c);
                return;
            }
            unLockLine(cstate->download_line);

            setupLineUpSide(cstate->main_line, onMainLinePaused, cstate, onMainLineResumed);
            setupLineDownSide(cstate->upload_line, onUDLinePaused, cstate, onUDLineResumed);
            setupLineDownSide(cstate->download_line, onUDLinePaused, cstate, onUDLineResumed);
            destroyContext(c);
        }
        else if (c->fin)
        {
            LSTATE_DROP(cstate->main_line);
            doneLineUpSide(cstate->main_line);
            cstate->main_line = NULL;
            destroyContext(c);

            line_t *upload_line   = cstate->upload_line;
            line_t *download_line = cstate->download_line;

            lockLine(download_line);

            cstate->upload_line = NULL;
            doneLineDownSide(upload_line);
            LSTATE_DROP(upload_line);
            self->up->upStream(self->up, newFinContext(upload_line));
            destroyLine(upload_line);

            if (! isAlive(download_line))
            {
                unLockLine(download_line);
                return;
            }
            unLockLine(download_line);

            cstate->download_line = NULL;
            doneLineDownSide(download_line);
            LSTATE_DROP(download_line);
            self->up->upStream(self->up, newFinContext(download_line));
            destroyLine(download_line);

            wwmGlobalFree(cstate);
        }
    }
}
static void downStream(tunnel_t *self, context_t *c)
{
    halfduplex_con_state_t *cstate = CSTATE(c);

    if (c->payload != NULL)
    {
        self->dw->downStream(self->dw, switchLine(c, cstate->main_line));
    }
    else
    {
        if (c->fin)
        {
            if (c->line == cstate->download_line)
            {
                LSTATE_DROP(cstate->download_line);
                doneLineDownSide(cstate->download_line);
                destroyLine(cstate->download_line);

                if (cstate->upload_line)
                {
                    LSTATE_DROP(cstate->upload_line);
                    doneLineDownSide(cstate->upload_line);
                    self->up->upStream(self->up, newFinContext(cstate->upload_line));
                    destroyLine(cstate->upload_line);
                }
            }
            else
            {
                LSTATE_DROP(cstate->upload_line);
                doneLineDownSide(cstate->upload_line);
                destroyLine(cstate->upload_line);

                if (cstate->download_line)
                {
                    LSTATE_DROP(cstate->download_line);
                    doneLineDownSide(cstate->download_line);
                    self->up->upStream(self->up, newFinContext(cstate->download_line));
                    destroyLine(cstate->download_line);
                }
            }
            if (cstate->main_line)
            {
                LSTATE_DROP(cstate->main_line);
                doneLineUpSide(cstate->main_line);
                self->dw->downStream(self->dw, newFinContext(cstate->main_line));
            }

            wwmGlobalFree(cstate);
            destroyContext(c);
        }
        else
        {
            if (c->line == cstate->download_line)
            {
                self->dw->downStream(self->dw, switchLine(c, cstate->main_line));
            }
            else
            {
                destroyContext(c);
            }
        }
    }
}

tunnel_t *newHalfDuplexClient(node_instance_context_t *instance_info)
{
    (void) instance_info;
    halfduplex_state_t *state = wwmGlobalMalloc(sizeof(halfduplex_state_t));
    memset(state, 0, sizeof(halfduplex_state_t));

    tunnel_t *t   = newTunnel();
    t->state      = state;
    t->upStream   = &upStream;
    t->downStream = &downStream;

    return t;
}

api_result_t apiHalfDuplexClient(tunnel_t *self, const char *msg)
{
    (void) (self);
    (void) (msg);
    return (api_result_t) {0};
}

tunnel_t *destroyHalfDuplexClient(tunnel_t *self)
{
    (void) (self);
    return NULL;
}
tunnel_metadata_t getMetadataHalfDuplexClient(void)
{
    return (tunnel_metadata_t) {.version = 0001, .flags = 0x0};
}
