/*
 * Covers: domainresolver flow; the explicit inputs, callbacks and expected results below define this
 * suite.
 * Setup: Real runtime/component code with the explicit worker/line/neighbour fixture and any linker
 * seams shown below. Line and buffer settlement remains the scenario owner's responsibility.
 * Cases: runBudget, runPressure, run
 * Checks: Assertion labels include: duplicated source Pause for overlapping pressure reasons; source Pause
 * preceded FIFO/accounting publication; adjacent Resume released DNS source hold; source Resume preceded
 * empty writable FIFO
 * Limits: Platform/feature branches remain conditional. Component fixtures do not establish host-network
 * or application-throughput behavior.
 * CTest: waterwall.domainresolver_flow_unit
 */
#include "DomainResolver/structure.h"
#include "fixtures/failure/tunnel_line_failure_harness.h"

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
static bool             use_prepare_state;
static unsigned         prepare_destroy_count;

static bool prepareLine(tunnel_t *t, tunnel_t *owner, line_t *l, void *state)
{
    twfRequire(t == resolver && owner == t->next && state == domainresolverTunnelGetUserLineState(t, l),
               "prepare hook received the wrong line or owner");
    domainresolver_tstate_t *ts = tunnelGetState(t);
    memorySet(state, 0x5A, ts->user_lstate_size);
    return true;
}

static void destroyPreparedLine(tunnel_t *t, tunnel_t *owner, line_t *l, void *state)
{
    twfRequire(t == resolver && owner == t->next && state == domainresolverTunnelGetUserLineState(t, l),
               "prepare destructor received the wrong line or owner");
    domainresolver_tstate_t *ts = tunnelGetState(t);
    for (uint32_t i = 0; i < ts->user_lstate_size; ++i)
        twfRequire(((uint8_t *) state)[i] == 0x5A, "prepare state or its padding was cleared before destruction");
    ++prepare_destroy_count;
}

static void requireBypassed(line_t *l)
{
    twfRequire(! tunnelIsActiveForLine(resolver, l), "settled resolver path was not bypassed");
    twfRequireLineStateZeroed(l, resolver, "bypassed resolver retained line or embedded prepare state");
}

static void closeInitiator(line_t *l)
{
    tunnelUpStreamFin(resolver, l);
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
    tunnelUpStreamPayload(resolver, l, payload(l, c));
}
static void pauseConsumer(line_t *l)
{
    tunnelDownStreamPause(resolver, l);
}
static void pauseSource(line_t *l)
{
    tunnelUpStreamPause(resolver, l);
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
    else if (pressure_only && pressure_action == 9)
    {
        pressure_action = 0;
        resumeConsumer(l);
        requireBypassed(l);
    }
}
static void resumeConsumer(line_t *l)
{
    tunnelDownStreamResume(resolver, l);
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
    twfRequire(tunnelIsActiveForLine(resolver, l), "resolver bypassed before next Init returned");
    if (use_prepare_state)
        twfRequire(prepare_destroy_count == 0 && *(uint8_t *) domainresolverTunnelGetUserLineState(resolver, l) == 0x5A,
                   "next Init lost its prepared state");
    if (finish_in_init)
    {
        tunnelDownStreamFin(resolver, l);
        return;
    }
    tunnelDownStreamEst(resolver, l);
    if (use_prepare_state && lineIsAlive(l))
        twfRequire(prepare_destroy_count == 0, "resolver retired prepare state during next Init reentry");
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
    node_t node = {.type = (char *) "DomainResolver"};
    resolver    = domainresolverTunnelCreate(&node);
    twfRequire(resolver != NULL, "failed to create resolver");
    tunnel_t *prev = tunnelCreate(NULL, 0, 0), *next = tunnelCreate(NULL, 0, 0);
    tunnelBind(prev, resolver);
    tunnelBind(resolver, next);
    prev->chain_index     = 0;
    resolver->chain_index = 1;
    next->chain_index     = 2;
    next->fnInitU    = onInit;
    prev->fnPayloadD = next->fnPayloadU = onPayload;
    prev->fnEstD                        = onEst;
    prev->fnPauseD = next->fnPauseU = onPause;
    prev->fnResumeD = next->fnResumeU = onResume;
    prev->fnFinD                      = ownerFinish;
    next->fnFinU                      = noop;
    domainresolver_tstate_t *ts       = tunnelGetState(resolver);
    ts->strategy                      = kDsOnlyIpV4;
    use_prepare_state                 = true;
    prepare_destroy_count             = 0;
    domainresolverTunnelSetPrepareHook(resolver, next, 33, prepareLine, destroyPreparedLine);
    twf_line_pool_t lines;
    twfLinePoolSetup(&lines, resolver->lstate_size, 1);
    /* The fixture keeps the pools; the chain owns only its exact packet line. */
    tunnel_chain_t *chain       = tunnelchainCreate(1);
    chain->contains_packet_node = true;
    chain->packet_lines         = memoryAllocate(sizeof(line_t *));
    chain->packet_lines[0]      = twfLinePoolCreateLine(&lines);
    resolver->chain             = chain;
    line_t *line                = twfLinePoolCreateLine(&lines);
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
    tunnelUpStreamInit(resolver, line);
    if (! literal)
    {
        twfRequire(init_count == 0 && dns_callback != NULL, "DNS wait reached adjacent Init");
        twfRequire(tunnelIsActiveForLine(resolver, line), "resolver bypassed before DNS completed");
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
        twfRequire(tunnelIsActiveForLine(resolver, line) && prepare_destroy_count == 0,
                   "resolver retired its paused startup backlog");
        inject_after_first = ! literal;
        resumeConsumer(line);
        if (! literal)
        {
            twfRequire(wire_length == 1 && wire[0] == 'A', "DNS release passed nested Pause or reordered input");
            twfRequire(tunnelIsActiveForLine(resolver, line), "resolver bypassed with older FIFO input retained");
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
        requireBypassed(line);
        twfRequire(prepare_destroy_count == 1, "resolver did not destroy prepare state exactly once before bypass");
        pressure_only        = true;
        unsigned ests_before = established_count;
        tunnelDownStreamEst(resolver, line);
        tunnelDownStreamEst(resolver, line);
        twfRequire(established_count == ests_before + 2, "bypassed resolver suppressed repeated Est");
        size_t bytes_before = wire_length;
        submit(line, 'D');
        tunnelDownStreamPayload(resolver, line, payload(line, 'E'));
        twfRequire(wire_length == bytes_before + 2 && wire[bytes_before] == 'D' && wire[bytes_before + 1] == 'E',
                   "bypassed resolver lost bidirectional payload");
        pauseConsumer(line);
        resumeConsumer(line);
        twfRequire(! initiating_source_paused, "bypassed resolver lost source pressure notifications");
        tunnelUpStreamFin(resolver, line);
        lineDestroy(line);
    }
    twfRequire(! lineIsAlive(line), "DNS close did not settle owner");
    twfRequire(prepare_destroy_count == 1, "Finish repeated or skipped prepare-state destruction");
    use_prepare_state = false;
    lineUnref(line);
    if (! close_now && literal)
    {
        line_t *packet = chain->packet_lines[0];
        addresscontextSetIpAddress(lineGetDestinationAddressContext(packet), "127.0.0.1");
        addresscontextSetPort(lineGetDestinationAddressContext(packet), 80);
        next->fnInitU = noop;
        tunnelUpStreamInit(resolver, packet);
        twfRequire(lineIsAlive(packet) && tunnelIsActiveForLine(resolver, packet) && prepare_destroy_count == 1,
                   "resolver bypassed or destroyed the chain's actual packet line");
        /* Worker-state teardown precedes the chain's final packet-line release. */
        domainresolverLinestateDestroy(resolver, packet, lineGetState(packet, resolver));
        twfRequire(prepare_destroy_count == 2, "packet prepare state was not destroyed exactly once");
    }
    tunnelchainDestroy(chain);
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
    node_t node = {.type = (char *) "DomainResolver"};
    resolver    = domainresolverTunnelCreate(&node);
    twfRequire(resolver != NULL, "failed to create resolver");
    tunnel_t *prev = tunnelCreate(NULL, 0, 0), *next = tunnelCreate(NULL, 0, 0);
    tunnelBind(prev, resolver);
    tunnelBind(resolver, next);
    prev->chain_index     = 0;
    resolver->chain_index = 1;
    next->chain_index     = 2;
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
    tunnelUpStreamInit(resolver, line);
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
                requireBypassed(line);
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
    tunnelDownStreamPayload(resolver, l, payload(l, 'R'));
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
    prev->chain_index                                                = 0;
    resolver->chain_index                                            = 1;
    next->chain_index                                                = 2;
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
    tunnelUpStreamInit(resolver, line);

    const size_t   limit  = 2U * 1024U * 1024U;
    const uint32_t length = (uint32_t) (limit - sizeof(sbuf_t) - kSbufAllocationAlignment - 64U);
    sbuf_t        *buf    = bufferpoolGetBestFit(lineGetBufferPool(line), length, 64);
    sbufSetLength(buf, length);
    memorySet(sbufGetMutablePtr(buf), 0xA5, length);
    twfRequire(sbufGetQueueCharge(buf) == limit, "fixture must reach the exact 2 MiB charge boundary");
    tunnelUpStreamPayload(resolver, line, buf);
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
        tunnelUpStreamPayload(resolver, line, empty);
        twfRequire(! lineIsAlive(line) && held_resume_count == 0, "empty buffer escaped allocation-charge limit");
        twfRequire(budget_next_finishes == (resolve_first ? 1U : 0U), "overflow finished an unopened next side");
    }
    else
    {
        resumeConsumer(line);
        twfRequire(budget_wire_bytes == length && held_resume_count == 1 && bufferqueueGetCharge(&ls->pending) == 0,
                   "large DNS backlog did not drain and release source pressure");
        requireBypassed(line);
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
    for (unsigned action = 0; action <= 9; ++action)
        runPressure(action);
    for (unsigned close_now = 0; close_now < 2; ++close_now)
        for (unsigned literal = 0; literal < 2; ++literal)
            run(close_now, literal);
    return 0;
}
