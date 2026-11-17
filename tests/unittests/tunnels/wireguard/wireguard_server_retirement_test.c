/* Real proof -> account refresh -> owner acknowledgments -> replacement proof.
 * Explicit message holds overlap old ingress, reverse output and inner affinity
 * with the range barrier; all production callbacks and cleanup paths run. */
#include "devices/device_flow_affinity.h"
#include "wireguard_server_fixture.h"

typedef struct held_s
{
    wid_t                        wid;
    WorkerMessageCallback        run;
    WorkerMessageCleanupCallback cancel;
    void                        *args[3];
} held_t;
static held_t   held[16];
static unsigned held_count, retirement_message;
static bool     hold_jobs, submitting_retirement;

void __real_ptcRetireSourceRange(tunnel_t *, const ip_addr_t *, const ip_addr_t *, wid_t, ptc_retire_complete_fn,
                                 void *);
void __wrap_ptcRetireSourceRange(tunnel_t *, const ip_addr_t *, const ip_addr_t *, wid_t, ptc_retire_complete_fn,
                                 void *);
void __wrap_ptcRetireSourceRange(tunnel_t *t, const ip_addr_t *network, const ip_addr_t *mask, wid_t coordinator,
                                 ptc_retire_complete_fn callback, void *context)
{
    submitting_retirement = true;
    __real_ptcRetireSourceRange(t, network, mask, coordinator, callback, context);
    submitting_retirement = false;
}
static bool holdMessage(wid_t wid, WorkerMessageCallback run, WorkerMessageCleanupCallback cancel, void *a, void *b,
                        void *c)
{
    if (! hold_jobs && ! (submitting_retirement && wid == wg_fixture->env.count - 1))
        return false;
    twfRequire(held_count < 16, "held message inventory overflow");
    if (submitting_retirement)
        retirement_message = held_count;
    held[held_count++] = (held_t) {.wid = wid, .run = run, .cancel = cancel, .args = {a, b, c}};
    return true;
}
static void releaseMessage(unsigned i)
{
    held_t job = held[i];
    twfRequire(job.run != NULL, "message settled twice");
    held[i].run          = NULL;
    const wid_t previous = tosSetCurrentWorker(job.wid);
    job.run(&wg_fixture->env.workers[job.wid], job.args[0], job.args[1], job.args[2]);
    discard tosSetCurrentWorker(previous);
}
static void insertAccount(users_t *users, uint64_t id, const char *password, const char *range, const char *name,
                          uint64_t generation)
{
    user_t user;
    twfRequire(userCreate(&user, password), "replacement account create failed");
    userSetId(&user, id);
    user.limit.ips      = 1;
    user.limit.cons_out = 8;
    twfRequire(userSetWireGuardAllowedIps(&user, range) && usersAddUser(users, &user),
               "replacement account insert failed");
    userDestroy(&user);
    user_t *stored = usersLookupByIdentifier(users, id);
    twfRequire(usersSetUserName(users, stored, name), "replacement account name failed");
    stored->runtime.identity_generation_floor  = generation;
    stored->runtime.wireguard_generation_floor = generation;
}
static void refresh(wg_server_fixture_t *f, unsigned change)
{
    users_t next;
    twfRequire(usersCreate(&next), "refresh create failed");
    const uint64_t generation = authenticationclientUsersGeneration(f->auth) + 1;
    insertAccount(&next,
                  42,
                  change ? "rotated-secret" : "wireguard-lifecycle-account",
                  change == 2 ? "10.51.0.4/30" : "10.50.0.4/30",
                  "account-a",
                  generation);
    insertAccount(&next, 44, "unaffected-secret", "10.60.0.2/32", "unaffected", generation);
    if (change == 2)
        insertAccount(&next, 43, "wireguard-lifecycle-account", "10.50.0.4/30", "replacement", generation);
    mutexLock(&f->as->control_mutex);
    rwlockWriteLock(&f->as->users_lock);
    twfRequire(usersMigrateRuntimeStateByIdentifier(&next, &f->users), "refresh migration failed");
    usersPublishCandidate(&f->users, &next);
    atomic_store(&f->as->users_generation, generation);
    rwlockWriteUnlock(&f->as->users_lock);
    mutexUnlock(&f->as->control_mutex);
    usersDestroy(&next);
}
static sbuf_t *packet(wg_server_fixture_t *f, uint8_t protocol, bool unaffected, bool reverse, wid_t owner)
{
    const unsigned length = protocol == 6 ? 40 : 29;
    sbuf_t        *buf    = bufferpoolGetSmallBuffer(f->env.pools[0]);
    sbufSetLength(buf, length);
    sbufWriteZeros(buf, length);
    uint8_t *p = sbufGetMutablePtr(buf);
    p[0]       = 0x45;
    PUT_BE16(p + 2, length);
    p[8] = 64;
    p[9] = protocol;
    ip_addr_t source, destination;
    twfRequire(ipaddr_aton(unaffected ? "10.60.0.2" : "10.50.0.5", &source) && ipaddr_aton("203.0.113.2", &destination),
               "inner address failed");
    memoryCopy(p + (reverse ? 16 : 12), &ip_2_ip4(&source)->addr, 4);
    memoryCopy(p + (reverse ? 12 : 16), &ip_2_ip4(&destination)->addr, 4);
    PUT_BE16(p + 22, 8080);
    if (protocol == 6)
    {
        PUT_BE32(p + 24, 1000);
        p[32] = 0x50;
        p[33] = TCP_SYN;
        PUT_BE16(p + 34, 16384);
    }
    else
    {
        PUT_BE16(p + 24, 9);
        p[28] = 42;
    }
    for (unsigned port = 40000; port < 65535; ++port)
    {
        PUT_BE16(p + 20, port);
        wid_t selected;
        twfRequire(deviceFlowAffineWID(p, length, &selected), "flow owner selection failed");
        if (selected == owner)
        {
            twfRequire(calcFullPacketChecksum(p, length), "inner checksum failed");
            return buf;
        }
    }
    twfRequire(false, "flow owner not found");
    return NULL;
}
static unsigned owned(wg_server_fixture_t *f, wid_t wid, const char *address)
{
    ptc_tstate_t *ptc = tunnelGetState(f->state->ptc);
    ip_addr_t     ip;
    twfRequire(ipaddr_aton(address, &ip), "owned filter invalid");
    unsigned count = 0;
    for (line_t *line = ptc->owned_lines[wid]; line;
         line         = ((ptc_lstate_t *) lineGetState(line, f->state->ptc))->owned_next)
        if (ipAddrCmp(&lineGetSourceAddressContext(line)->ip_address, &ip))
            ++count;
    return count;
}
static void requireProtocolsEmpty(wg_server_fixture_t *f)
{
    ptc_tstate_t *ptc = tunnelGetState(f->state->ptc);
    for (wid_t wid = 0; wid < f->env.count; ++wid)
    {
        twfRequire(owned(f, wid, "10.50.0.5") == 0, "affected normal line survived retirement");
        interface_route_context_t *route = ptc->routes_v4[wid];
        if (! route)
            continue;
        const wid_t       previous = tosSetCurrentWorker(wid);
        ww_lwip_engine_t *previous_engine;
        twfRequire(wwLwipEngineEnter(route->engine, &previous_engine), "protocol inspection enter failed");
        ip_addr_t affected;
        twfRequire(ipaddr_aton("10.50.0.5", &affected), "affected address failed");
        for (struct udp_pcb *pcb = udp_pcbs; pcb; pcb = pcb->next)
            twfRequire(pcb == route->udp_pcb || ! ipAddrCmp(&pcb->remote_ip, &affected),
                       "affected preline UDP survived");
        for (struct tcp_pcb *pcb = tcp_active_pcbs; pcb; pcb = pcb->next)
            twfRequire(! ipAddrCmp(&pcb->remote_ip, &affected), "affected preline TCP survived");
        wwLwipEngineLeave(route->engine, previous_engine);
        discard tosSetCurrentWorker(previous);
    }
    twfRequire(ptc->drain_count == 0, "affected drain survived retirement");
}
static void proveOther(wg_server_fixture_t *f, wireguard_device_t *other)
{
    wireguard_device_t saved = f->client;
    f->client                = (wireguard_device_t) {0};
    char    private_key[45]  = {0};
    user_t *account          = usersLookupByIdentifier(&f->users, 44);
    twfRequire(wwBase64Encode(account->sha256_pass.bytes, 32, private_key) == 44, "unaffected key failed");
    twfRequire(
        wireguardCommonInit(
            &f->client, private_key, f, (wireguard_callbacks_t) {.output = wgClientOutput, .inner = wgClientInner}),
        "unaffected client failed");
    cJSON *peer =
        cJSON_Parse("{\"publickey\":\"GnRcOavdc180YrXak138cZxWlMoEUZL0Mg/ZyWhLBgo=\",\"allowedips\":\"0.0.0.0/0\"}");
    uint8_t index;
    twfRequire(wireguardCommonAddConfiguredPeer(&f->client, peer, &index), "unaffected peer failed");
    cJSON_Delete(peer);
    twfRequire(wireguardifStartHandshake(&f->client, &f->client.peers[0], true) == ERR_OK,
               "unaffected initiation failed");
    wgServerFixtureExchange(f);
    twfRequire(f->state->bindings[1].usable && f->state->bindings[1].authorization.handle.user_id == 44,
               "unaffected proof failed");
    wireguardCommonSendInner(&f->client, packet(f, 17, true, false, 0));
    wgServerFixtureExchange(f);
    *other    = f->client;
    f->client = saved;
}
static void scenario(wid_t workers)
{
    held_count = 0;
    wg_server_fixture_t f;
    wgServerFixtureSetup(&f, workers, "");
    refresh(&f, 0);
    twfRequire(wwStartupSucceeded(wgServerFixtureStart(&f)), "server startup failed");
    wgServerFixtureProof(&f);
    const uint64_t     old_epoch = f.state->bindings[0].epoch;
    wireguard_device_t unaffected;
    proveOther(&f, &unaffected);
    const uint64_t unaffected_epoch = f.state->bindings[1].epoch;
    discard        tosSetCurrentWorker(0);
    wireguardCommonSendInner(&f.client, packet(&f, 17, false, false, workers - 1));
    wireguardCommonSendInner(&f.client, packet(&f, 6, false, false, workers - 1));
    wgServerFixtureExchange(&f);
    twfRequire(owned(&f, workers - 1, "10.50.0.5") > 0 && owned(&f, 0, "10.60.0.2") > 0, "real PTC admission missing");
    refresh(&f, 0);
    reconcile(f.state);
    twfRequire(f.state->bindings[0].epoch == old_epoch && f.state->bindings[0].usable,
               "unchanged refresh replaced binding");

    wg_submit_hook = holdMessage;
    hold_jobs      = true;
    wireguardCommonSendInner(&f.client, packet(&f, 17, false, false, workers - 1));
    twfRequire(wireguardifStartHandshake(&f.client, &f.client.peers[0], true) == ERR_OK, "held initiation failed");
    const wid_t ingress_wid = workers - 1;
    discard     tosSetCurrentWorker(ingress_wid);
    for (unsigned i = 0; i < f.server_count; ++i)
        tunnelNextUpStreamPayload(f.adapter, f.ingress[ingress_wid], f.to_server[i]);
    f.server_count = 0;
    discard tosSetCurrentWorker(0);
    payloadDown(f.server, tunnelchainGetWorkerPacketLine(f.chain, 0), packet(&f, 17, false, true, 0));
    binding_t *binding  = &f.state->bindings[0];
    sbuf_t    *old_send = bufferpoolGetSmallBuffer(f.env.pools[0]);
    sbufSetLength(old_send, 32);
    sbufWriteZeros(old_send, 32);
    twfRequire(output(f.state, old_send, &f.state->engine.peers[0], &binding->ingress->ip, binding->ingress->port),
               "old output hold failed");
    const unsigned held_dispatches = atomic_load(&f.state->dispatch.count);
    /* A real UDP child exists before its queued Init and payload can run. */
    sbuf_t  *deferred = packet(&f, 17, false, false, workers - 1);
    uint8_t *bytes    = sbufGetMutablePtr(deferred);
    PUT_BE16(bytes + 22, 8081);
    for (unsigned port = 41000; port < 65535; ++port)
    {
        PUT_BE16(bytes + 20, port);
        wid_t selected;
        twfRequire(deviceFlowAffineWID(bytes, sbufGetLength(deferred), &selected), "deferred owner selection failed");
        if (selected == workers - 1)
            break;
    }
    twfRequire(calcFullPacketChecksum(bytes, sbufGetLength(deferred)), "deferred checksum failed");
    discard        tosSetCurrentWorker(workers - 1);
    const unsigned before_deferred = held_count;
    ptcTunnelUpStreamPayload(f.state->ptc, tunnelchainGetWorkerPacketLine(f.chain, workers - 1), deferred);
    if (held_count == before_deferred + 1)
        releaseMessage(before_deferred); /* Cross-worker affinity first reaches the protocol owner. */
    twfRequire(held_count >= before_deferred + 2 && owned(&f, workers - 1, "10.50.0.5") >= 2,
               "deferred real PTC Init/payload was not held");
    discard tosSetCurrentWorker(0);
    hold_jobs                  = false;
    const unsigned stale_count = held_count;
    twfRequire(stale_count >= 4, "stale ingress/reverse/send work was not retained");
    sbuf_t *stale_affinity = packet(&f, 17, false, false, workers - 1);
    refresh(&f, 1);
    reconcile(f.state);
    twfRequire(binding->retiring && ! binding->usable && ! atomic_load(&binding->retirement_done),
               "range barrier did not close");
    for (wid_t wid = 0; wid < workers; ++wid)
        tosPumpWorker(&f.env, wid);
    twfRequire(! atomic_load(&binding->retirement_done), "held owner acknowledgment was bypassed");
    f.state->receiving_generation = authenticationclientUsersGeneration(f.auth);
    user_t *rotated               = usersLookupByIdentifier(&f.users, 42);
    twfRequire(candidate(f.state, rotated->wireguard_publickey) == NULL, "candidate overlapped retiring range");
    refresh(&f, 2); /* A further update must win over an outstanding lookup. */
    f.state->receiving_generation = authenticationclientUsersGeneration(f.auth);
    user_t *replacement           = usersLookupByIdentifier(&f.users, 43);
    twfRequire(candidate(f.state, replacement->wireguard_publickey) == NULL,
               "replacement published before owner barrier");
    releaseMessage(retirement_message);
    wgServerFixturePump(&f);
    reconcile(f.state);
    requireProtocolsEmpty(&f);
    twfRequire(usersLookupByIdentifier(&f.users, 42)->runtime.active_cons_out == 0, "old identity leaked reservations");
    twfRequire(wireguardifStartHandshake(&f.client, &f.client.peers[0], true) == ERR_OK,
               "replacement initiation failed");
    wgServerFixtureExchangePending(&f, held_dispatches);
    twfRequire(f.client.peers[0].curr_keypair.valid && f.state->engine.peers[0].curr_keypair.valid,
               "replacement proof failed to derive keys");
    twfRequire(binding->epoch != old_epoch && binding->authorization.handle.user_id == 43 &&
                   f.state->bindings[1].epoch == unaffected_epoch && f.state->bindings[1].usable,
               "replacement proof adopted stale identity or disturbed unaffected peer");
    const unsigned opened = f.opened, output_count = f.client_count;
    for (unsigned i = 0; i < stale_count; ++i)
        if (held[i].run != NULL)
            releaseMessage(i);
    discard tosSetCurrentWorker(workers - 1);
    packetAffinityForwardTagged(((ptc_tstate_t *) tunnelGetState(f.state->ptc))->input_affinity,
                                tunnelchainGetWorkerPacketLine(f.chain, workers - 1),
                                stale_affinity,
                                old_epoch);
    wgServerFixturePump(&f);
    twfRequire(f.opened == opened && f.client_count == output_count && binding->usable &&
                   binding->authorization.handle.user_id == 43,
               "stale queued work escaped the replacement epoch");
    requireProtocolsEmpty(&f);
    discard tosSetCurrentWorker(0);
    wireguardCommonSendInner(&f.client, packet(&f, 17, false, false, workers - 1));
    wgServerFixtureExchange(&f);
    twfRequire(f.opened == opened + 1 && usersLookupByIdentifier(&f.users, 43)->runtime.active_cons_out == 1,
               "fresh replacement traffic did not use current identity/reservation");
    twfRequire(usersLookupByIdentifier(&f.users, 44)->runtime.active_cons_out == 1, "unaffected reservation changed");
    wg_submit_hook = NULL;
    wireguardDeviceDestroy(&unaffected);
    wgServerFixtureClose(&f, wwLifecycleProcessShutdown());
}
int main(void)
{
    testCaseSet("wireguard_server_retirement_test");
    scenario(1);
    scenario(4);
    return 0;
}
