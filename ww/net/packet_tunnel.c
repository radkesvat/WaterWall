#include "packet_tunnel.h"
#include "line.h"
#include "loggers/internal_logger.h"

// Default upstream initialization function
void packettunnelDefaultUpStreamInit(tunnel_t *self, line_t *line)
{
    assert(self->next != NULL);
    self->next->fnInitU(self->next, line);
}

// Default upstream establishment function
void packettunnelDefaultUpStreamEst(tunnel_t *self, line_t *line)
{
    assert(self->next != NULL);
    self->next->fnEstU(self->next, line);
}

// Default upstream finalization function
void packettunnelDefaultUpStreamFin(tunnel_t *self, line_t *line)
{
    assert(self->next != NULL);
    self->next->fnFinU(self->next, line);
}

// Default upstream payload function
void packettunnelDefaultUpStreamPayload(tunnel_t *self, line_t *line, sbuf_t *payload)
{
    discard self;
    discard line;
    discard payload;
    LOGF("Unexpected call to default up stream payload for a packet tunnel, this function must be overridden");
    terminateProgram(1);
}

// Default upstream pause function
void packettunnelDefaultUpStreamPause(tunnel_t *self, line_t *line)
{
    assert(self->next != NULL);
    self->next->fnPauseU(self->next, line);
}

// Default upstream resume function
void packettunnelDefaultUpStreamResume(tunnel_t *self, line_t *line)
{
    assert(self->next != NULL);
    self->next->fnResumeU(self->next, line);
}

// Default downstream initialization function
void packettunnelDefaultdownStreamInit(tunnel_t *self, line_t *line)
{
    discard self;
    discard line;
    LOGF("Unexpected call to default down stream init for a packet tunnel");
    terminateProgram(1);
}

// Default downstream establishment function
void packettunnelDefaultdownStreamEst(tunnel_t *self, line_t *line)
{
    discard self;
    discard line;
    if (self->prev != NULL)
    {
        self->prev->fnEstD(self->prev, line);
    }
    // if (! line->established)
    // {
    //     self->prev->fnEstD(self->prev, line);
    // }
    // LOGD("packet tunnel blocked down stream est");
}

// Default downstream finalization function
void packettunnelDefaultdownStreamFinish(tunnel_t *self, line_t *line)
{
    assert(self->prev != NULL);
    LOGD("packet tunnel received Finish, forcing line to recreate");
    // if (line->established)
    // {
    self->next->fnInitU(self->next, line);
    // }
    // else
    // {
    // self->prev->fnEstD(self->prev, line);
    // }
}

// Default downstream payload function
void packettunnelDefaultdownStreamPayload(tunnel_t *self, line_t *line, sbuf_t *payload)
{
    discard self;
    discard line;
    discard payload;
    LOGF("Unexpected call to default down stream payload for a packet tunnel, this function must be overridden");
    terminateProgram(1);
}

// Default downstream pause function
void packettunnelDefaultDownStreamPause(tunnel_t *self, line_t *line)
{
    if (self->prev != NULL)
    {
        self->next->fnPauseD(self->next, line);
    }
}

// Default downstream resume function
void packettunnelDefaultDownStreamResume(tunnel_t *self, line_t *line)
{
    if (self->prev != NULL)
    {
        self->next->fnResumeD(self->next, line);
    }
}

tunnel_t *packettunnelCreate(node_t *node, uint16_t tstate_size, uint16_t lstate_size)
{
    assert(lstate_size == 0); // packet tunnels dont have lines
    discard lstate_size;
    tunnel_t *t = tunnelCreate(node, tstate_size, 0);

    t->fnInitU    = packettunnelDefaultUpStreamInit;
    t->fnEstU     = packettunnelDefaultUpStreamEst;
    t->fnFinU     = packettunnelDefaultUpStreamFin;
    t->fnPayloadU = packettunnelDefaultUpStreamPayload;
    t->fnPauseU   = packettunnelDefaultUpStreamPause;
    t->fnResumeU  = packettunnelDefaultUpStreamResume;

    t->fnInitD    = packettunnelDefaultdownStreamInit;
    t->fnEstD     = packettunnelDefaultdownStreamEst;
    t->fnFinD     = packettunnelDefaultdownStreamFinish;
    t->fnPayloadD = packettunnelDefaultdownStreamPayload;
    t->fnPauseD   = packettunnelDefaultDownStreamPause;
    t->fnResumeD  = packettunnelDefaultDownStreamResume;

    return t;
}
