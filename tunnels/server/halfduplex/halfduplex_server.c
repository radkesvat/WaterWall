#include "halfduplex_server.h"
#include "basic_types.h"
#include "hmutex.h"
#include "loggers/network_logger.h"
#include "pipe_line.h"
#include "shiftbuffer.h"
#include "tunnel.h"
#include "utils/jsonutils.h"
#include <stdatomic.h>
#include <stdint.h>
#include <stdlib.h>

#define i_type hmap_lines_t                    // NOLINT
#define i_key  hash_t                          // NOLINT
#define i_val  halfduplex_server_con_state_t * // NOLINT

enum
{
    kHmapCap = 16 * 4
};

#include "stc/hmap.h"

typedef struct halfduplex_server_state_s
{
    hhybridmutex_t hmap_mutex;

    hmap_lines_t upload_line_map;
    hmap_lines_t download_line_map;

} halfduplex_server_state_t;

typedef struct halfduplex_server_con_state_s
{
    atomic_bool ready;

    shift_buffer_t *buffering;
    pipe_line_t *_Atomic pipe;

    line_t *main_line;
    line_t *upload_line;
    line_t *download_line;

} halfduplex_server_con_state_t;

static void upStream(tunnel_t *self, context_t *c)
{
    halfduplex_server_state_t     *state  = STATE(self);
    halfduplex_server_con_state_t *cstate = CSTATE(c);
    if (c->payload != NULL)
    {
        // todo (buffering) do the buffering
        assert(bufLen(c->payload) >= 8);
        shift_buffer_t *buf = c->payload;

        bool ready = atomic_load_explicit(&(cstate->ready), memory_order_acquire);

        if (ready)
        {
        }
        else
        {
            pipe_line_t *pipe = atomic_load_explicit(&(cstate->pipe), memory_order_relaxed);
            if (pipe)
            {
            }
            else
            {

                const bool is_upload = (((uint8_t *) rawBuf(c->payload))[0] & 0x80) == 0x0;

                hash_t hash = 0x0;
                readUI64(c->payload, (uint64_t *) &hash);
                hash = hash & (0x7FFFFFFFFFFFFFFFULL);

                shiftr(buf, sizeof(uint64_t));

                if (is_upload)
                {
                    hhybridmutex_lock(&(state->hmap_mutex));
                    hmap_lines_t_iter f_iter = hmap_lines_t_find(&(state->download_line_map), hash);
                    if (f_iter.ref == hmap_lines_t_end(&(state->download_line_map)).ref)
                    {
                        if (! hmap_lines_t_push(&(state->download_line_map), cstate))
                        {
                            reuseContextBuffer(c);
                            destroyContext(c);
                        }
                    }
                    else
                    {
                    }

                    hhybridmutex_unlock(&(state->hmap_mutex));
                }
                else
                {
                }
            }
        }
    }
    else
    {
        if (c->init)
        {
            cstate  = malloc(sizeof(halfduplex_server_con_state_t));
            *cstate = (halfduplex_server_con_state_t){
                .buffering = NULL, .pipe = NULL, .main_line = NULL, .upload_line = NULL, .download_line = NULL};

            CSTATE_MUT(c) = cstate;
            self->dw->downStream(self->dw, newEstContext(c->line));
            destroyContext(c);
        }
        else if (c->fin)
        {
        }
    }
}

static void downStream(tunnel_t *self, context_t *c)
{

    halfduplex_server_state_t     *state  = STATE(self);
    halfduplex_server_con_state_t *cstate = CSTATE(c);
    if (c->payload != NULL)
    {
        self->dw->downStream(self->dw, c);
    }
    else
    {
        if (c->fin)
        {
        }
        else if (c->est)
        {
        }
    }
}

tunnel_t *newHalfDuplexServer(node_instance_context_t *instance_info)
{

    halfduplex_server_state_t *state = malloc(sizeof(halfduplex_server_state_t));
    memset(state, 0, sizeof(halfduplex_server_state_t));

    hhybridmutex_init(&state->hmap_mutex);

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
