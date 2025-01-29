#include "tunnel.h"
#include "pipe_line.h"


static void defaultPipeTunnelUpStreamInit(tunnel_t *self, line_t *line)
{
    assert(self->up != NULL);
    if(isUpPiped(line)){
        pipeUpStream(context_t *c)
    }
    self->up->fnInitU(self->up, line);
}

static void defaultPipeTunnelUpStreamEst(tunnel_t *self, line_t *line)
{
    assert(self->up != NULL);
    self->up->fnEstU(self->up, line);
}

static void defaultPipeTunnelUpStreamFin(tunnel_t *self, line_t *line)
{
    assert(self->up != NULL);
    self->up->fnFinU(self->up, line);
}

static void defaultPipeTunnelUpStreamPayload(tunnel_t *self, line_t *line, sbuf_t *payload)
{
    assert(self->up != NULL);
    self->up->fnPayloadU(self->up, line, payload);
}

static void defaultPipeTunnelUpStreamPause(tunnel_t *self, line_t *line)
{
    assert(self->up != NULL);
    self->up->fnPauseU(self->up, line);
}

static void defaultPipeTunnelUpStreamResume(tunnel_t *self, line_t *line)
{
    assert(self->up != NULL);
    self->up->fnResumeU(self->up, line);
}

static void defaultPipeTunnelUpStreamGetBufInfo(tunnel_t *self, tunnel_buffinfo_t *info)
{
    assert(info->len < kMaxChainLen);

    info->tuns[(info->len)++] = self;

    assert(self->up != NULL);
    self->up->fnGBufInfoU(self->up, info);
}

static void defaultPipeTunneldownStreamInit(tunnel_t *self, line_t *line)
{
    assert(self->dw != NULL);
    self->up->fnInitD(self->up, line);
}

static void defaultPipeTunneldownStreamEst(tunnel_t *self, line_t *line)
{
    assert(self->dw != NULL);
    self->up->fnEstD(self->up, line);
}

static void defaultPipeTunneldownStreamFin(tunnel_t *self, line_t *line)
{
    assert(self->dw != NULL);
    self->up->fnFinD(self->up, line);
}

static void defaultPipeTunneldownStreamPayload(tunnel_t *self, line_t *line, sbuf_t *payload)
{
    assert(self->dw != NULL);
    self->up->fnPayloadD(self->up, line, payload);
}

static void defaultPipeTunnelDownStreamPause(tunnel_t *self, line_t *line)
{
    assert(self->dw != NULL);
    self->up->fnPauseD(self->up, line);
}

static void defaultPipeTunnelDownStreamResume(tunnel_t *self, line_t *line)
{
    assert(self->dw != NULL);
    self->up->fnResumeD(self->up, line);
}

static void defaultPipeTunnelDownStreamGetBufInfo(tunnel_t *self, tunnel_buffinfo_t *info)
{
    assert(info->len < kMaxChainLen);

    info->tuns[(info->len)++] = self;

    assert(self->dw != NULL);
    self->up->fnGBufInfoD(self->up, info);
}

static void defaultPipeTunnelOnChainingComplete(tunnel_t *self)
{
    (void) self;
}

static void defaultPipeTunnelBeforeChainStart(tunnel_t *self)
{
    (void) self;
}

static void defaultPipeTunnelOnChainStart(tunnel_t *self)
{
    (void) self;
}

tunnel_t *tunnelCreate(uint16_t tstate_size, uint16_t lstate_size)
{
    tunnel_t *ptr = memoryAllocate(sizeof(tunnel_t) + tstate_size);

    *ptr = (tunnel_t) {.lstate_size        = lstate_size,
                       .fnInitU            = &defaultPipeTunnelUpStreamInit,
                       .fnInitD            = &defaultPipeTunneldownStreamInit,
                       .fnPayloadU         = &defaultPipeTunnelUpStreamPayload,
                       .fnPayloadD         = &defaultPipeTunneldownStreamPayload,
                       .fnEstU             = &defaultPipeTunnelUpStreamEst,
                       .fnEstD             = &defaultPipeTunneldownStreamEst,
                       .fnFinU             = &defaultPipeTunnelUpStreamFin,
                       .fnFinD             = &defaultPipeTunneldownStreamFin,
                       .fnPauseU           = &defaultPipeTunnelUpStreamPause,
                       .fnPauseD           = &defaultPipeTunnelDownStreamPause,
                       .fnResumeU          = &defaultPipeTunnelUpStreamResume,
                       .fnResumeD          = &defaultPipeTunnelDownStreamResume,
                       .fnGBufInfoU        = &defaultPipeTunnelUpStreamGetBufInfo,
                       .fnGBufInfoD        = &defaultPipeTunnelDownStreamGetBufInfo,
                       .onChainingComplete = &defaultPipeTunnelOnChainingComplete,
                       .beforeChainStart   = &defaultPipeTunnelBeforeChainStart,
                       .onChainStart       = &defaultPipeTunnelOnChainStart};
    


    return ptr;
}



 

