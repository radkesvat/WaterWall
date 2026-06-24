#pragma once

#include "wwapi.h"

typedef enum domainresolver_direction_e
{
    kDomainResolverDirectionNone = 0,
    kDomainResolverDirectionUpstream,
    kDomainResolverDirectionDownstream
} domainresolver_direction_t;

typedef enum domainresolver_phase_e
{
    kDomainResolverPhaseIdle = 0,
    kDomainResolverPhaseResolving,
    kDomainResolverPhaseOpen
} domainresolver_phase_t;

typedef struct domainresolver_tstate_s
{
    enum domain_strategy strategy;
    bool                 verbose;
    bool                 use_line_strategy;
    bool                 allow_missing_destination;
} domainresolver_tstate_t;

typedef struct domainresolver_lstate_s
{
    buffer_queue_t             pending;
    domainresolver_phase_t     phase;
    domainresolver_direction_t init_direction;
} domainresolver_lstate_t;

enum
{
    kDomainResolverPendingQueueInitialCapacity = 4,
    kDomainResolverMaxPendingBytes             = 1024 * 1024,
    kTunnelStateSize                           = sizeof(domainresolver_tstate_t),
    kLineStateSize                             = sizeof(domainresolver_lstate_t)
};

WW_EXPORT void         domainresolverTunnelDestroy(tunnel_t *t);
WW_EXPORT tunnel_t    *domainresolverTunnelCreate(node_t *node);
WW_EXPORT api_result_t domainresolverTunnelApi(tunnel_t *instance, sbuf_t *message);

void domainresolverTunnelOnStop(tunnel_t *t);

void domainresolverTunnelUpStreamInit(tunnel_t *t, line_t *l);
void domainresolverTunnelUpStreamEst(tunnel_t *t, line_t *l);
void domainresolverTunnelUpStreamFinish(tunnel_t *t, line_t *l);
void domainresolverTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void domainresolverTunnelUpStreamPause(tunnel_t *t, line_t *l);
void domainresolverTunnelUpStreamResume(tunnel_t *t, line_t *l);

void domainresolverTunnelDownStreamInit(tunnel_t *t, line_t *l);
void domainresolverTunnelDownStreamEst(tunnel_t *t, line_t *l);
void domainresolverTunnelDownStreamFinish(tunnel_t *t, line_t *l);
void domainresolverTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void domainresolverTunnelDownStreamPause(tunnel_t *t, line_t *l);
void domainresolverTunnelDownStreamResume(tunnel_t *t, line_t *l);

void domainresolverLinestateInitialize(domainresolver_lstate_t *ls);
void domainresolverLinestateDestroy(domainresolver_lstate_t *ls);

bool domainresolverStartResolveIfNeeded(tunnel_t *t, line_t *l, domainresolver_lstate_t *ls,
                                        domainresolver_direction_t direction, bool *started_out);
bool domainresolverQueueResolvingPayload(tunnel_t *t, line_t *l, domainresolver_lstate_t *ls, sbuf_t *buf,
                                         domainresolver_direction_t direction);
void domainresolverCloseBeforeInit(tunnel_t *t, line_t *l, domainresolver_direction_t direction);
void domainresolverCloseLine(tunnel_t *t, line_t *l, domainresolver_direction_t direction);
