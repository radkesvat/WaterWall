#include "egress_pin.h"

#include "global_state.h"
#include "loggers/internal_logger.h"
#include "wsocket.h"

/*
 * Synchronization note: refs and pin fields are plain globals because node
 * lifecycle set/clear is currently serialized, and fields are immutable while a
 * pin is active. If lifecycle and socket creation become concurrent, guard this
 * state with a lock or publish an atomic snapshot.
 */
void egressPinSet(const char *ifname, uint32_t idx_v4, uint32_t idx_v6)
{
    if (GSTATE.tun_egress_pin_refs > 0)
    {
        GSTATE.tun_egress_pin_refs++;
        LOGI("EgressPin: reused existing pin (refs=%u)", GSTATE.tun_egress_pin_refs);
        return;
    }

    GSTATE.tun_egress_ifindex_v4 = idx_v4;
    GSTATE.tun_egress_ifindex_v6 = idx_v6;
    GSTATE.tun_egress_ifname[0]  = '\0';

    if (ifname != NULL && ifname[0] != '\0')
    {
        stringCopyN(GSTATE.tun_egress_ifname, ifname, sizeof(GSTATE.tun_egress_ifname));
    }

    GSTATE.tun_egress_pin_refs = 1;
    atomicStoreExplicit(&GSTATE.tun_egress_pin_active, true, memory_order_release);
    LOGI("EgressPin: active (ifname=%s v4_idx=%u v6_idx=%u)",
         GSTATE.tun_egress_ifname,
         idx_v4,
         idx_v6);
}

void egressPinClear(void)
{
    if (GSTATE.tun_egress_pin_refs == 0)
    {
        atomicStoreExplicit(&GSTATE.tun_egress_pin_active, false, memory_order_release);
        return;
    }

    GSTATE.tun_egress_pin_refs--;
    if (GSTATE.tun_egress_pin_refs > 0)
    {
        LOGI("EgressPin: retained existing pin (refs=%u)", GSTATE.tun_egress_pin_refs);
        return;
    }

    atomicStoreExplicit(&GSTATE.tun_egress_pin_active, false, memory_order_release);
    GSTATE.tun_egress_ifname[0]    = '\0';
    GSTATE.tun_egress_ifindex_v4   = 0;
    GSTATE.tun_egress_ifindex_v6   = 0;
}

bool egressPinActive(void)
{
    return atomicLoadExplicit(&GSTATE.tun_egress_pin_active, memory_order_acquire);
}

int egressPinApply(int sockfd, int family, const char *explicit_ifname)
{
    if (explicit_ifname != NULL && explicit_ifname[0] != '\0')
    {
        return 0;
    }

    if (! egressPinActive())
    {
        return 0;
    }

#if defined(OS_WIN)
    if (family == AF_INET)
    {
        uint32_t idx = GSTATE.tun_egress_ifindex_v4;
        if (idx == 0)
        {
            return 0;
        }
        DWORD idx_be = htonl(idx);
        return setsockopt(sockfd, IPPROTO_IP, IP_UNICAST_IF, (const char *) &idx_be, sizeof(idx_be));
    }
    if (family == AF_INET6)
    {
        uint32_t idx = GSTATE.tun_egress_ifindex_v6;
        if (idx == 0)
        {
            return 0;
        }
        DWORD idx_host = idx;
        return setsockopt(sockfd, IPPROTO_IPV6, IPV6_UNICAST_IF, (const char *) &idx_host, sizeof(idx_host));
    }
    return 0;
#elif defined(OS_LINUX) && defined(SO_BINDTODEVICE)
    discard family;
    if (GSTATE.tun_egress_ifname[0] == '\0')
    {
        return 0;
    }
    return setsockopt(sockfd,
                      SOL_SOCKET,
                      SO_BINDTODEVICE,
                      GSTATE.tun_egress_ifname,
                      (socklen_t) (stringLength(GSTATE.tun_egress_ifname) + 1));
#else
    discard sockfd;
    discard family;
    return 0;
#endif
}
