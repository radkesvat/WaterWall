#include "DomainResolver/structure.h"
#include "tunnel_line_failure_harness.h"

static tunnel_t        *resolver;
static LineDnsResolveFn dns_callback;
static line_t          *dns_line;
static tunnel_t        *dns_tunnel;
static void            *dns_userdata;
static bool             finish_in_init, inject_after_first;
static char             wire[8];
static size_t           wire_length;
static unsigned         established_count, init_count, source_pause_count;
static unsigned         held_pause_count, held_resume_count, pressure_action;
static bool             pressure_only, initiating_source_paused;

static void closeInitiator(line_t *l)
{
    domainresolverTunnelUpStreamFinish(resolver, l);
    lineDestroy(l);
}
static bool isInitiatingSource(tunnel_t *t)
{
    return t == resolver->prev;
}
static void resumeConsumer(line_t *l);

int __wrap_lineResolveDomainServiceAsync(line_t *line, const char *domain, const char *service, int socktype,
                                         LineDnsResolveFn callback, tunnel_t *t, void *userdata);
int __wrap_lineResolveDomainServiceAsync(line_t *line, const char *domain, const char *service, int socktype,
                                         LineDnsResolveFn callback, tunnel_t *t, void *userdata)
{
    discard domain;
    discard service;
    discard socktype;
    dns_callback = callback;
    dns_line     = line;
    dns_tunnel   = t;
    dns_userdata = userdata;
    lineRef(line);
    return ARES_SUCCESS;
}

static sbuf_t *payload(line_t *l, char c)
{
    sbuf_t *buf = bufferpoolGetSmallBuffer(lineGetBufferPool(l));
    sbufSetLength(buf, 1);
    sbufGetMutablePtr(buf)[0] = (uint8_t) c;
    return buf;
}
static void submit(line_t *l, char c)
{
    domainresolverTunnelUpStreamPayload(resolver, l, payload(l, c));
}
static void pauseConsumer(line_t *l)
{
    domainresolverTunnelDownStreamPause(resolver, l);
}
static void pauseSource(line_t *l)
{
    domainresolverTunnelUpStreamPause(resolver, l);
}
static void onPause(tunnel_t *t, line_t *l)
{
    if (! isInitiatingSource(t))
    {
        ++source_pause_count;
        return;
    }
    ++held_pause_count;
    twfRequire(! initiating_source_paused, "duplicated source Pause for overlapping pressure reasons");
    initiating_source_paused    = true;
    domainresolver_lstate_t *ls = lineGetState(l, resolver);
    if (ls->pending_source_hold)
        twfRequire(bufferqueueGetBufCount(&ls->pending) != 0 && bufferqueueGetCharge(&ls->pending) != 0,
                   "source Pause preceded FIFO/accounting publication");
    if (pressure_only && pressure_action == 1)
    {
        pressure_action = 0;
        submit(l, 'B');
    }
    else if (pressure_only && pressure_action == 2)
    {
        pressure_action = 0;
        closeInitiator(l);
    }
    else if (pressure_only && pressure_action == 3)
    {
        pressure_action = 0;
        resumeConsumer(l);
        twfRequire(held_resume_count == 0, "adjacent Resume released DNS source hold");
        submit(l, 'B');
    }
}
static void onResume(tunnel_t *t, line_t *l)
{
    if (! isInitiatingSource(t))
        return;
    domainresolver_lstate_t *ls = lineGetState(l, resolver);
    twfRequire(initiating_source_paused && ! ls->pending_source_hold && bufferqueueGetBufCount(&ls->pending) == 0 &&
                   bufferqueueGetCharge(&ls->pending) == 0 && ! ls->next_paused,
               "source Resume preceded empty writable FIFO");
    initiating_source_paused = false;
    ++held_resume_count;
    if (pressure_only && pressure_action == 5)
    {
        pressure_action = 0;
        submit(l, 'C');
        pauseConsumer(l);
    }
    else if (pressure_only && pressure_action == 6)
    {
        pressure_action = 0;
        closeInitiator(l);
    }
}
static void resumeConsumer(line_t *l)
{
    domainresolverTunnelDownStreamResume(resolver, l);
}
static void noop(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;
}
static void ownerFinish(tunnel_t *t, line_t *l)
{
    discard t;
    lineDestroy(l);
}
static void onEst(tunnel_t *t, line_t *l)
{
    discard t;
    ++established_count;
    if (pressure_only)
        return;
    submit(l, 'B');
    pauseSource(l);
    pauseConsumer(l);
}
static void onInit(tunnel_t *t, line_t *l)
{
    discard t;
    ++init_count;
    if (finish_in_init)
    {
        domainresolverTunnelDownStreamFinish(resolver, l);
        return;
    }
    domainresolverTunnelDownStreamEst(resolver, l);
}
static void onPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    discard t;
    twfRequire(sbufGetLength(buf) == 1 && wire_length < sizeof(wire), "resolver changed payload boundary");
    wire[wire_length++] = *(const char *) sbufGetRawPtr(buf);
    lineReuseBuffer(l, buf);
    if (pressure_only && pressure_action == 7)
    {
        pressure_action = 0;
        closeInitiator(l);
        return;
    }
    if (inject_after_first)
    {
        inject_after_first = false;
        submit(l, 'C');
        pauseConsumer(l);
    }
}

static void run(bool close_now, bool literal)
{
    twfSetCase("DomainResolver preserves DNS FIFO across Init/Est/Pause reentry");
    twf_worker_env_t env;
    twfWorkerEnvSetup(&env, 4096, 32);
    resolver       = tunnelCreate(NULL, sizeof(domainresolver_tstate_t), sizeof(domainresolver_lstate_t));
    tunnel_t *prev = tunnelCreate(NULL, 0, 0), *next = tunnelCreate(NULL, 0, 0);
    tunnelBind(prev, resolver);
    tunnelBind(resolver, next);
    next->fnInitU    = onInit;
    prev->fnPayloadD = next->fnPayloadU = onPayload;
    prev->fnEstD                        = onEst;
    prev->fnPauseD = next->fnPauseU = onPause;
    prev->fnResumeD = next->fnResumeU = onResume;
    prev->fnFinD                      = ownerFinish;
    next->fnFinU                      = noop;
    domainresolver_tstate_t *ts       = tunnelGetState(resolver);
    ts->strategy                      = kDsOnlyIpV4;
    twf_line_pool_t lines;
    twfLinePoolSetup(&lines, resolver->lstate_size, 1);
    line_t *line = twfLinePoolCreateLine(&lines);
    lineRef(line);
    address_context_t *dest = lineGetDestinationAddressContext(line);
    if (literal)
        addresscontextSetIpAddress(dest, "127.0.0.1");
    else
        addresscontextDomainSet(dest, "resolver.invalid", 16);
    addresscontextSetPort(dest, 80);
    addresscontextSetOnlyProtocol(dest, IP_PROTO_TCP);
    pressure_only    = false;
    held_pause_count = held_resume_count = pressure_action = 0;
    initiating_source_paused                               = false;

    finish_in_init     = close_now;
    inject_after_first = false;
    init_count = established_count = wire_length = source_pause_count = 0;
    dns_callback                                                      = NULL;
    domainresolverTunnelUpStreamInit(resolver, line);
    if (! literal)
    {
        twfRequire(init_count == 0 && dns_callback != NULL, "DNS wait reached adjacent Init");
        submit(line, 'A');
        pauseSource(line);
        dns_resolved_addr_t answer = {.family = AF_INET, .addrlen = sizeof(struct sockaddr_in)};
        struct sockaddr_in *addr   = (struct sockaddr_in *) &answer.addr;
        addr->sin_family           = AF_INET;
        addr->sin_addr.s_addr      = htonl(INADDR_LOOPBACK);
        dns_callback(dns_tunnel, dns_line, dns_userdata, ARES_SUCCESS, NULL, &answer, 1);
        lineUnref(dns_line);
    }
    if (! close_now)
    {
        twfRequire(init_count == 1 && established_count == 1 && wire_length == 0,
                   "resolver did not forward Est promptly while retaining paused backlog");
        twfRequire(held_pause_count == 1 && held_resume_count == 0, "DNS/order pressure was not held exactly once");
        twfRequire(source_pause_count == 1, "DNS Init replay duplicated an already forwarded source Pause");
        inject_after_first = ! literal;
        resumeConsumer(line);
        if (! literal)
        {
            twfRequire(wire_length == 1 && wire[0] == 'A', "DNS release passed nested Pause or reordered input");
            resumeConsumer(line);
            twfRequire(wire_length == 3 && memoryEqual(wire, "ABC", 3), "DNS FIFO changed after Resume");
        }
        else
            twfRequire(wire_length == 1 && wire[0] == 'B', "literal Init reentry lost input");
        twfRequire(held_resume_count == 1 && ! initiating_source_paused,
                   "completed FIFO failed to release source pressure");
        domainresolver_lstate_t *ls = lineGetState(line, resolver);
        twfRequire(bufferqueueGetCharge(&ls->pending) == 0 && bufferqueueGetBufCount(&ls->pending) == 0,
                   "DNS drain leaked charge");
        domainresolverTunnelUpStreamFinish(resolver, line);
        lineDestroy(line);
    }
    twfRequire(! lineIsAlive(line), "DNS close did not settle owner");
    lineUnref(line);
    twfRequireNoLeakedBuffers();
    twfLinePoolTeardown(&lines);
    tunnelDestroy(next);
    tunnelDestroy(prev);
    tunnelDestroy(resolver);
    twfWorkerEnvTeardown(&env);
}
static void runPressure(unsigned action)
{
    twfSetCase("DomainResolver holds initiating source through DNS and FIFO callback reentry");
    twf_worker_env_t env;
    twfWorkerEnvSetup(&env, 4096, 32);
    resolver       = tunnelCreate(NULL, sizeof(domainresolver_tstate_t), sizeof(domainresolver_lstate_t));
    tunnel_t *prev = tunnelCreate(NULL, 0, 0), *next = tunnelCreate(NULL, 0, 0);
    tunnelBind(prev, resolver);
    tunnelBind(resolver, next);
    next->fnInitU    = onInit;
    prev->fnPayloadD = next->fnPayloadU = onPayload;
    prev->fnEstD                        = onEst;
    prev->fnPauseD = next->fnPauseU = onPause;
    prev->fnResumeD = next->fnResumeU                                = onResume;
    prev->fnFinD                                                     = ownerFinish;
    next->fnFinU                                                     = noop;
    ((domainresolver_tstate_t *) tunnelGetState(resolver))->strategy = kDsOnlyIpV4;
    twf_line_pool_t lines;
    twfLinePoolSetup(&lines, resolver->lstate_size, 1);
    line_t *line = twfLinePoolCreateLine(&lines);
    lineRef(line);
    address_context_t *dest = lineGetDestinationAddressContext(line);
    addresscontextDomainSet(dest, "resolver.invalid", 16);
    addresscontextSetPort(dest, 80);
    addresscontextSetOnlyProtocol(dest, IP_PROTO_TCP);

    pressure_only   = true;
    pressure_action = action;
    finish_in_init = inject_after_first = initiating_source_paused = false;
    init_count = established_count = wire_length = source_pause_count = held_pause_count = held_resume_count = 0;
    domainresolverTunnelUpStreamInit(resolver, line);
    if (action == 4)
        pauseConsumer(line);
    submit(line, 'A');
    twfRequire(held_pause_count == 1 && held_resume_count == 0 && wire_length == 0,
               "first retained input did not stop initiating source");
    if (lineIsAlive(line))
    {
        domainresolver_lstate_t *ls = lineGetState(line, resolver);
        twfRequire(ls->pending_source_hold && ! ls->prev_paused, "DNS hold was stored as received read permission");
        resumeConsumer(line);
        twfRequire(held_resume_count == 0, "Resume bypassed unresolved DNS gate");
        if (action == 8)
        {
            // Tiny inputs remain bounded by allocation charge, including buffer overhead.
            const size_t max_buffers = kDomainResolverMaxPendingBytes / bufferqueueGetCharge(&ls->pending);
            unsigned     admitted    = 1;
            while (lineIsAlive(line) && admitted <= max_buffers)
            {
                submit(line, 'x');
                ++admitted;
            }
            twfRequire(! lineIsAlive(line) && held_resume_count == 0, "DNS charge overflow survived or resumed source");
        }
        else
        {
            dns_resolved_addr_t answer = {.family = AF_INET, .addrlen = sizeof(struct sockaddr_in)};
            struct sockaddr_in *addr   = (struct sockaddr_in *) &answer.addr;
            addr->sin_family           = AF_INET;
            addr->sin_addr.s_addr      = htonl(INADDR_LOOPBACK);
            dns_callback(dns_tunnel, dns_line, dns_userdata, ARES_SUCCESS, NULL, &answer, 1);
            if (action == 6 || action == 7)
                twfRequire(! lineIsAlive(line), "DNS source callback close left line alive");
            else
            {
                const char *expected = action == 1 || action == 3 ? "AB" : action == 5 ? "AC" : "A";
                twfRequire(wire_length == strlen(expected) && memoryEqual(wire, expected, wire_length),
                           "source pressure reentry reordered bytes");
                twfRequire(init_count == 1 && established_count == 1 && held_resume_count == 1,
                           "pressure stopped DNS/Est or failed final source release");
                if (action == 5)
                    twfRequire(held_pause_count == 2 && initiating_source_paused,
                               "Resume callback's new adjacent Pause was overwritten");
            }
        }
    }
    lineUnref(dns_line); // Mock DNS service releases its delivery reference, even after close.
    if (lineIsAlive(line))
        closeInitiator(line);
    twfRequireLineStateZeroed(line, resolver, "DNS pressure close left line state");
    lineUnref(line);
    twfRequireNoLeakedBuffers();
    twfLinePoolTeardown(&lines);
    tunnelDestroy(next);
    tunnelDestroy(prev);
    tunnelDestroy(resolver);
    twfWorkerEnvTeardown(&env);
}

static size_t   budget_wire_bytes;
static unsigned budget_next_finishes, budget_replies;

static void onBudgetReply(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    discard t;
    twfRequire(sbufGetLength(buf) == 1 && ((const char *) sbufGetRawPtr(buf))[0] == 'R',
               "DNS Init changed downstream reply");
    ++budget_replies;
    lineReuseBuffer(l, buf);
}

static void onBudgetInit(tunnel_t *t, line_t *l)
{
    onInit(t, l);
    domainresolverTunnelDownStreamPayload(resolver, l, payload(l, 'R'));
}

static void onBudgetPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    discard        t;
    const uint8_t *bytes = sbufGetRawPtr(buf);
    for (uint32_t i = 0; i < sbufGetLength(buf); ++i)
        twfRequire(bytes[i] == 0xA5, "DNS backlog changed large payload bytes");
    budget_wire_bytes += sbufGetLength(buf);
    lineReuseBuffer(l, buf);
}

static void onBudgetFinish(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;
    ++budget_next_finishes;
}

static void runBudget(bool overflow, bool resolve_first)
{
    twfSetCase("DomainResolver accepts 2 MiB charge and closes on the next retained allocation");
    twf_worker_env_t env;
    twfWorkerEnvSetup(&env, 4096, 32);
    node_t node = {.type = (char *) "DomainResolver"};
    resolver    = domainresolverTunnelCreate(&node);
    twfRequire(resolver != NULL, "failed to create resolver");
    twfRequire(resolver->fnInitD == tunnelDefaultDownStreamInit && resolver->fnEstU == tunnelDefaultUpStreamEst,
               "resolver must inherit rejection of unsupported lifecycle directions");
    tunnel_t *prev = tunnelCreate(NULL, 0, 0), *next = tunnelCreate(NULL, 0, 0);
    tunnelBind(prev, resolver);
    tunnelBind(resolver, next);
    prev->fnEstD                                                     = onEst;
    prev->fnPayloadD                                                 = onBudgetReply;
    prev->fnPauseD                                                   = onPause;
    prev->fnResumeD                                                  = onResume;
    prev->fnFinD                                                     = ownerFinish;
    next->fnInitU                                                    = onBudgetInit;
    next->fnPayloadU                                                 = onBudgetPayload;
    next->fnFinU                                                     = onBudgetFinish;
    ((domainresolver_tstate_t *) tunnelGetState(resolver))->strategy = kDsOnlyIpV4;
    twf_line_pool_t lines;
    twfLinePoolSetup(&lines, resolver->lstate_size, 1);
    line_t *line = twfLinePoolCreateLine(&lines); // Fixture-owned normal line; resolver only borrows it.
    lineRef(line);
    address_context_t *dest = lineGetDestinationAddressContext(line);
    addresscontextDomainSet(dest, "resolver.invalid", 16);
    addresscontextSetPort(dest, 80);
    addresscontextSetOnlyProtocol(dest, IP_PROTO_TCP);
    finish_in_init = inject_after_first = initiating_source_paused = false;
    pressure_only                                                  = true;
    pressure_action = held_pause_count = held_resume_count = init_count = established_count = 0;
    budget_wire_bytes = budget_next_finishes = budget_replies = 0;
    domainresolverTunnelUpStreamInit(resolver, line);

    const size_t   limit  = 2U * 1024U * 1024U;
    const uint32_t length = (uint32_t) (limit - sizeof(sbuf_t) - kSbufAllocationAlignment - 64U);
    sbuf_t        *buf    = bufferpoolGetBestFit(lineGetBufferPool(line), length, 64);
    sbufSetLength(buf, length);
    memorySet(sbufGetMutablePtr(buf), 0xA5, length);
    twfRequire(sbufGetQueueCharge(buf) == limit, "fixture must reach the exact 2 MiB charge boundary");
    domainresolverTunnelUpStreamPayload(resolver, line, buf);
    twfRequire(lineIsAlive(line), "valid payload above 1 MiB was refused");
    domainresolver_lstate_t *ls = lineGetState(line, resolver);
    twfRequire(bufferqueueGetCharge(&ls->pending) == limit && bufferqueueGetBufLen(&ls->pending) == length,
               "DNS pending budget lost buffer ownership or charge");

    if (resolve_first)
    {
        pauseConsumer(line);
        dns_resolved_addr_t answer = {.family = AF_INET, .addrlen = sizeof(struct sockaddr_in)};
        struct sockaddr_in *addr   = (struct sockaddr_in *) &answer.addr;
        addr->sin_family           = AF_INET;
        addr->sin_addr.s_addr      = htonl(INADDR_LOOPBACK);
        dns_callback(dns_tunnel, dns_line, dns_userdata, ARES_SUCCESS, NULL, &answer, 1);
        twfRequire(init_count == 1 && established_count == 1 && budget_replies == 1 && budget_wire_bytes == 0,
                   "DNS completion drained through Pause or deferred Est/downstream reply");
    }
    if (overflow)
    {
        sbuf_t *empty = bufferpoolGetSmallBuffer(lineGetBufferPool(line));
        sbufSetLength(empty, 0);
        domainresolverTunnelUpStreamPayload(resolver, line, empty);
        twfRequire(! lineIsAlive(line) && held_resume_count == 0, "empty buffer escaped allocation-charge limit");
        twfRequire(budget_next_finishes == (resolve_first ? 1U : 0U), "overflow finished an unopened next side");
    }
    else
    {
        resumeConsumer(line);
        twfRequire(budget_wire_bytes == length && held_resume_count == 1 && bufferqueueGetCharge(&ls->pending) == 0,
                   "large DNS backlog did not drain and release source pressure");
        closeInitiator(line);
    }
    lineUnref(dns_line); // Mock delivery reference also settles after pre-resolution overflow.
    twfRequireLineStateZeroed(line, resolver, "budget close left resolver state");
    lineUnref(line);
    twfRequireNoLeakedBuffers();
    twfLinePoolTeardown(&lines);
    tunnelDestroy(next);
    tunnelDestroy(prev);
    tunnelDestroy(resolver);
    twfWorkerEnvTeardown(&env);
}

int main(void)
{
    runBudget(false, true);
    runBudget(true, false);
    runBudget(true, true);
    for (unsigned action = 0; action <= 8; ++action)
        runPressure(action);
    for (unsigned close_now = 0; close_now < 2; ++close_now)
        for (unsigned literal = 0; literal < 2; ++literal)
            run(close_now, literal);
    return 0;
}
