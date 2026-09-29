#include "engine.h"
#include "engine_internal.h"
#include "lwip/inet_chksum.h"
#include "lwip/ip.h"
#include "lwip/netif.h"
#include "lwip/priv/tcp_priv.h"
#include "lwip/timeouts.h"
#include "lwip/udp.h"

#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "lwip_engine_test_runtime.h"

/* The private raw-stack fixture supplies the OS boundary, with two fixed owners.
 * A barrier inside real TCP output / UDP input proves overlapping protocol dispatch. */
static pthread_barrier_t rendezvous;
static struct netif      interfaces[2];
static unsigned          received[2];
static unsigned          sent[2];
static unsigned          timed[2];
static ww_lwip_engine_t *engines[2];

static void checkModuleAccessGuard(bool enter, enum ww_lwip_state_module module)
{
    /* Fork before starting workers: each expected fatal access gets a private
     * engine copy and cannot leave the shared fixture partially initialized. */
    pid_t child = fork();
    CHECK(child >= 0);
    if (child == 0)
    {
        struct rlimit no_core = {0, 0};
        if (setrlimit(RLIMIT_CORE, &no_core) != 0)
            _exit(2);
        if (enter)
        {
            owner                    = 0;
            owner_loop               = (struct wloop_s *) &interfaces[0];
            ww_lwip_engine_t *engine = wwLwipEngineCreate(0, (struct wloop_s *) owner_loop);
            ww_lwip_engine_t *previous;
            if (engine == NULL || ! wwLwipEngineEnter(engine, &previous))
                _exit(2);
        }
        (void) wwLwipModuleState(module);
        _exit(1);
    }
    int status;
    CHECK(waitpid(child, &status, 0) == child);
    CHECK(WIFSIGNALED(status) && WTERMSIG(status) == SIGABRT);
}

static void meet(void)
{
    int rc = pthread_barrier_wait(&rendezvous);
    CHECK(rc == 0 || rc == PTHREAD_BARRIER_SERIAL_THREAD);
}

static err_t output(struct netif *netif, struct pbuf *packet, const ip4_addr_t *destination)
{
    (void) destination;
    CHECK(netif == &interfaces[owner]);
    CHECK(packet->tot_len >= 40);
    CHECK(ip_data.current_input_netif == netif);
    ++sent[owner];
    struct pbuf *nested = pbuf_alloc(PBUF_RAW, 20, PBUF_RAM);
    CHECK(nested != NULL);
    CHECK(wwLwipEngineInput(wwLwipEngineCurrent(), nested, netif) == ERR_ARG);
    pbuf_free(nested);
    meet(); /* Both threads must reach TCP SYN-ACK output concurrently. */
    CHECK(ip_data.current_input_netif == netif);
    return ERR_OK;
}

static void onTimeout(void *argument)
{
    CHECK(argument == &interfaces[owner]);
    CHECK(wwLwipEngineCurrent() == engines[owner]);
    ++timed[owner];
    meet();
}

static err_t init_netif(struct netif *netif)
{
    netif->name[0] = 't';
    netif->name[1] = 'e';
    netif->mtu     = 1500;
    netif->output  = output;
    return ERR_OK;
}

static void receiveUdp(void *arg, struct udp_pcb *pcb, struct pbuf *p, const ip_addr_t *address, u16_t port)
{
    (void) arg;
    (void) address;
    CHECK(pcb == udp_pcbs);
    CHECK(port == 5000);
    CHECK(p->tot_len == 1);
    CHECK(*(uint8_t *) p->payload == owner);
    CHECK(ip_data.current_input_netif == &interfaces[owner]);
    meet();
    CHECK(ip_data.current_input_netif == &interfaces[owner]);
    ++received[owner];
    pbuf_free(p);
}

static void inject(ww_lwip_engine_t *engine, bool tcp)
{
    uint8_t  packet[40] = {0x45, 0, 0, 0, 0, 0, 0, 0, 64};
    unsigned length     = tcp ? 40 : 29;
    packet[3]           = (uint8_t) length;
    packet[9]           = tcp ? 6 : 17;
    packet[12]          = 10;
    packet[15]          = 2;
    packet[16]          = 10;
    packet[19]          = 1;
    packet[20]          = 0x13;
    packet[21]          = 0x88; /* peer 5000 */
    packet[22]          = tcp ? 0x04 : 0x10;
    packet[23]          = tcp ? 0xd2 : 0xe1;
    if (tcp)
    {
        packet[27]         = 10;
        packet[32]         = 0x50;
        packet[33]         = TCP_SYN;
        packet[34]         = 0x40;
        uint8_t pseudo[32] = {0};
        memcpy(pseudo, packet + 12, 8);
        pseudo[9]  = 6;
        pseudo[11] = 20;
        memcpy(pseudo + 12, packet + 20, 20);
        uint16_t sum = (uint16_t) ~wwLwipChecksum(pseudo, sizeof(pseudo));
        memcpy(packet + 36, &sum, 2);
    }
    else
    {
        packet[25] = 9;
        packet[28] = (uint8_t) owner;
    }
    uint16_t sum = (uint16_t) ~wwLwipChecksum(packet, 20);
    memcpy(packet + 10, &sum, 2);
    struct pbuf *p = pbuf_alloc(PBUF_RAW, (u16_t) length, PBUF_RAM);
    CHECK(p != NULL);
    CHECK(pbuf_take(p, packet, (u16_t) length) == ERR_OK);
    CHECK(wwLwipEngineInput(engine, p, &interfaces[owner]) == ERR_OK);
}

static void *run(void *arg)
{
    owner                    = (unsigned) (uintptr_t) arg;
    owner_loop               = (struct wloop_s *) &interfaces[owner];
    ww_lwip_engine_t *engine = wwLwipEngineCreate((uint8_t) owner, (struct wloop_s *) &interfaces[owner]);
    CHECK(engine != NULL);
    engines[owner] = engine;
    CHECK(wwLwipEngineCurrent() == NULL);
    ww_lwip_engine_t *previous;
    CHECK(wwLwipEngineEnter(engine, &previous));
    ip4_addr_t address, mask, gateway;
    IP4_ADDR(&address, 10, 0, 0, 1);
    IP4_ADDR(&mask, 255, 255, 255, 0);
    ip4_addr_set_zero(&gateway);
    CHECK(netif_add(&interfaces[owner], &address, &mask, &gateway, NULL, init_netif, ip_input) != NULL);
    netif_set_up(&interfaces[owner]);
    netif_set_link_up(&interfaces[owner]);
    struct udp_pcb *udp = udp_new();
    CHECK(udp != NULL);
    CHECK(udp_bind(udp, IP_ADDR_ANY, 4321) == ERR_OK);
    CHECK(udp_bind_netif(udp, &interfaces[owner]) == ERR_OK);
    udp_recv(udp, receiveUdp, NULL);
    struct tcp_pcb *tcp = tcp_new();
    CHECK(tcp != NULL);
    CHECK(tcp_bind(tcp, IP_ADDR_ANY, 1234) == ERR_OK);
    CHECK(tcp_bind_netif(tcp, &interfaces[owner]) == ERR_OK);
    struct tcp_pcb *listener = tcp_listen(tcp);
    CHECK(listener != NULL);
    meet();
    ww_lwip_engine_t *foreign_previous = NULL;
    CHECK(! wwLwipEngineEnter(engines[1 - owner], &foreign_previous));
    CHECK(wwLwipEngineCurrent() == engine);
    CHECK(interfaces[0].num == interfaces[1].num);
    CHECK(interfaces[0].ww_generation == interfaces[1].ww_generation);
    CHECK(udp_bind_netif(udp, &interfaces[1 - owner]) == ERR_ARG);
    CHECK(udp->netif_idx == netif_get_index(&interfaces[owner]));
    inject(engine, true);
    CHECK(tcp_active_pcbs != NULL && tcp_active_pcbs->next == NULL);
    CHECK(tcp_active_pcbs->state == SYN_RCVD);
    struct tcp_pcb *live = tcp_active_pcbs;
    for (unsigned i = 0; i < 100; ++i)
        inject(engine, false);
    CHECK(received[owner] == 100 && sent[owner] == 1);
    sys_timeout(10, onTimeout, &interfaces[owner]);
    meet();
    if (owner == 0)
        atomic_store(&clock_ms, 10);
    meet();
    wwLwipEngineCheckTimeouts(engine);
    CHECK(timed[owner] == 1);
    wwLwipEngineLeave(engine, previous);
    meet();
    if (owner == 0)
    {
        wwLwipEngineDestroy(engine);
        engine = wwLwipEngineCreate(0, (struct wloop_s *) &interfaces[0]);
        CHECK(engine != NULL);
        CHECK(wwLwipEngineEnter(engine, &previous));
        CHECK(tcp_active_pcbs == NULL && udp_pcbs == NULL);
        wwLwipEngineLeave(engine, previous);
        wwLwipEngineDestroy(engine);
    }
    meet();
    if (owner == 1)
    {
        CHECK(wwLwipEngineEnter(engine, &previous));
        CHECK(tcp_active_pcbs == live && live->state == SYN_RCVD);
        CHECK(udp_pcbs == udp && udp->local_port == 4321);
        wwLwipEngineLeave(engine, previous);
        wwLwipEngineDestroy(engine);
    }
    CHECK(wwLwipEngineCurrent() == NULL);
    return NULL;
}

int main(void)
{
    wwLwipEngineSharedInit();
    checkModuleAccessGuard(false, kWwLwipState_tcp);
    checkModuleAccessGuard(true, kWwLwipStateCount);
    checkModuleAccessGuard(true, (enum ww_lwip_state_module) - 1);
    CHECK(pthread_barrier_init(&rendezvous, NULL, 2) == 0);
    pthread_t threads[2];
    for (uintptr_t i = 0; i < 2; ++i)
        CHECK(pthread_create(&threads[i], NULL, run, (void *) i) == 0);
    for (unsigned i = 0; i < 2; ++i)
        CHECK(pthread_join(threads[i], NULL) == 0);
    CHECK(pthread_barrier_destroy(&rendezvous) == 0);
    printf("two concurrent engines: %zu control bytes each\n", wwLwipEngineControlSize());
    wwLwipEngineSharedCleanup();
    return 0;
}
