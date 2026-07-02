#pragma once

#include "wwapi.h"

typedef enum router_sniff_result_e
{
    kRouterSniffDone     = 0,
    kRouterSniffNeedMore = 1
} router_sniff_result_t;

enum
{
    kRouterSniffHttp1 = 1U << 0U,
    kRouterSniffTls   = 1U << 1U,
    kRouterSniffQuic  = 1U << 2U,
    kRouterSniffHttp2 = 1U << 3U
};

enum
{
    kRouterAttributeHttpUpgradePresent = 1U << 0U
};

struct router_tstate_s;
struct router_match_ctx_s;

bool                  routerLoadSniffing(struct router_tstate_s *ts, const cJSON *settings);
router_sniff_result_t routerSniffRun(struct router_tstate_s *ts, struct router_match_ctx_s *mctx);
