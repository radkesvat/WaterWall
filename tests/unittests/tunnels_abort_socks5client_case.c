#include "Socks5Client/structure.h"

#include "tunnels_abort_runtime_cases.h"

static int rejectUdpInit(socks5client_line_kind_t kind)
{
    cJSON *settings = cJSON_Parse("{\"target-address\":\"127.0.0.1\",\"port\":1080,\"protocol\":\"udp\"}");
    if (settings == NULL)
    {
        return kAbortCaseAllocationFailed;
    }
    node_t    node = {.node_settings_json = settings};
    tunnel_t *t    = socks5clientTunnelCreate(&node);
    if (t == NULL)
    {
        cJSON_Delete(settings);
        return kAbortCaseAllocationFailed;
    }
    line_t *l = memoryAllocateCacheAlignedZero(sizeof(line_t) + t->lstate_size);
    if (l == NULL)
    {
        socks5clientTunnelDestroy(t, wwLifecycleStartupRollback());
        cJSON_Delete(settings);
        return kAbortCaseAllocationFailed;
    }
    atomic_init(&l->refc, 1);
    l->alive                  = true;
    l->wid                    = 0;
    socks5client_lstate_t *ls = lineGetState(l, t);
    ls->kind                  = kind;
    t->fnInitD(t, l);

    memoryFreeAligned(l);
    socks5clientTunnelDestroy(t, wwLifecycleStartupRollback());
    cJSON_Delete(settings);
    return 0;
}

int tunnelsAbortSocks5ClientUdpAppInitCase(void)
{
    return rejectUdpInit(kSocks5ClientLineKindUdpApp);
}

int tunnelsAbortSocks5ClientUdpControlInitCase(void)
{
    return rejectUdpInit(kSocks5ClientLineKindUdpControl);
}

int tunnelsAbortSocks5ClientUdpRelayInitCase(void)
{
    return rejectUdpInit(kSocks5ClientLineKindUdpRelay);
}
