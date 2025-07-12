#include "structure.h"

#include "loggers/network_logger.h"

void ptcUdpReceived(void *arg, struct udp_pcb *upcb, struct pbuf *p, const ip_addr_t *addr, u16_t port)
{
    LWIP_UNUSED_ARG(arg);
    LWIP_UNUSED_ARG(upcb);
    LWIP_UNUSED_ARG(addr);
    LWIP_UNUSED_ARG(port);
    // LOGD("Udp Received %d bytes from %s:%d", p->len, ip4AddrNetworkToAddress(addr), port);
    // printHex("UDP Data", p->payload, max(6,p->len));



    pbuf_free(p);
}
