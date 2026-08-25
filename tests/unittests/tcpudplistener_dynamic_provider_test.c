#include "TcpUdpListener/structure.h"
#include "UdpListener/interface.h"

static void require(bool condition, const char *message)
{
    if (! condition)
    {
        fprintf(stderr, "%s\n", message);
        exit(1);
    }
}

int main(void)
{
    tunnel_t *wrapper = tunnelCreate(NULL, sizeof(tcpudplistener_tstate_t), 0);
    tunnel_t *child   = tunnelCreate(NULL, 0, 0);
    require(wrapper != NULL && child != NULL, "failed to create TcpUdpListener provider delegation fixture");

    tcpudplistener_tstate_t *state = tunnelGetState(wrapper);
    state->udp_listener            = child;

    const udplistener_dynamic_provider_t delegated = tcpudplistenerGetDynamicProvider(wrapper);
    const udplistener_dynamic_provider_t direct    = udplistenerGetDynamicProvider(child);
    require(delegated.instance == child, "TcpUdpListener did not delegate the private UdpListener instance");
    require(delegated.open == direct.open && delegated.activate == direct.activate && delegated.close == direct.close &&
                delegated.get_line_info == direct.get_line_info,
            "TcpUdpListener did not return the exact private UdpListener provider capability");

    state->udp_listener                         = NULL;
    const udplistener_dynamic_provider_t absent = tcpudplistenerGetDynamicProvider(wrapper);
    require(absent.instance == NULL && absent.open == NULL && absent.activate == NULL && absent.close == NULL &&
                absent.get_line_info == NULL,
            "TcpUdpListener reported a provider without its private UdpListener child");

    tunnelDestroy(child);
    tunnelDestroy(wrapper);
    puts("tcpudplistener_dynamic_provider_test: all cases passed");
    return 0;
}
