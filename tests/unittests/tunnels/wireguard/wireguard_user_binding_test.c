/* Real binding helper and UserController with a fixture normal-line creator.
 * PTC metadata is initialized explicitly; the scoped PTC engine suite covers
 * protocol/flow retirement. CTest: waterwall.wireguard_user_binding_unit */
#include "fixtures/failure/tunnel_line_failure_harness.h"
#include "fixtures/user_runtime.h"
#define kTunnelStateSize kAuthStateSize
#define kLineStateSize   kAuthLineSize
#include "AuthenticationClient/structure.h"
#undef kTunnelStateSize
#undef kLineStateSize
#include "../../../../../tunnels/WireGuardServer/server.c"
#include "PacketsToConnection/structure.h"

/* Only the absent control transport is stubbed: correlated response parsing,
 * sticky rejection and Session recovery remain the production transitions. */
void authenticationclientHandleResponseFrame(tunnel_t *, line_t *, uint8_t, uint32_t, const uint8_t *, uint32_t,
                                             uint64_t, uint64_t, uint64_t);
bool authenticationclientPendingAppend(authenticationclient_tstate_t *, uint32_t, uint8_t, uint64_t);
void __wrap_authenticationclientRecoverControlLine(tunnel_t *, line_t *, bool);
void __wrap_authenticationclientResumeSync(tunnel_t *);
void __wrap_authenticationclientRecoverControlLine(tunnel_t *t, line_t *line, bool finish)
{
    discard t;
    discard finish;
    twfRequire(line == NULL, "fixture unexpectedly owns a control line");
}
void __wrap_authenticationclientResumeSync(tunnel_t *t)
{
    discard t;
}

static unsigned int proof_millis = 10000;
unsigned int        __wrap_getTickMS(void);
unsigned int        __wrap_getTickMS(void)
{
    return proof_millis;
}

typedef struct proof_s
{
    wireguard_device_t client;
    sbuf_t            *requests[16], *responses[16];
    unsigned           requests_count, responses_count;
    ingress_t         *ingress;
    server_t          *state;
} proof_t;
static proof_t *proving;
static bool     proofOutput(void *context, sbuf_t *packet, wireguard_peer_t *peer, const ip_addr_t *ip, uint16_t port)
{
    discard  peer;
    discard  ip;
    discard  port;
    proof_t *proof = proving;
    twfRequire(proof != NULL, "proof output without exchange");
    if (context == &proof->client)
    {
        twfRequire(proof->requests_count < 16, "proof request overflow");
        proof->requests[proof->requests_count++] = packet;
    }
    else
    {
        twfRequire(proof->responses_count < 16, "proof response overflow");
        proof->responses[proof->responses_count++] = packet;
    }
    return true;
}
static void exchangeProof(proof_t *proof)
{
    proving = proof;
    proof_millis += 1000;
    twfRequire(wireguardifStartHandshake(&proof->client, &proof->client.peers[0], true) == ERR_OK,
               "client initiation failed");
    for (unsigned round = 0; round < 16 && (proof->requests_count || proof->responses_count); ++round)
    {
        while (proof->requests_count)
        {
            sbuf_t *packet                     = proof->requests[--proof->requests_count];
            proof->state->receiving            = proof->ingress;
            proof->state->receiving_generation = authenticationclientUsersGeneration(proof->state->auth);
            wireguardCommonReceive(&proof->state->engine, packet, &proof->ingress->ip, proof->ingress->port);
            proof->state->receiving = NULL;
        }
        while (proof->responses_count)
            wireguardCommonReceive(
                &proof->client, proof->responses[--proof->responses_count], &proof->ingress->ip, 51820);
    }
    proving = NULL;
}
static void setupProof(proof_t *proof, server_t *state, const char *password)
{
    *proof = (proof_t) {.state = state};
    sha256_hash_t digest;
    twfRequire(wCryptoSHA256(&digest, (const uint8_t *) password, strlen(password)) == kWCryptoOk,
               "private key failed");
    char encoded[45] = {0};
    wwBase64Encode(digest.bytes, sizeof(digest.bytes), encoded);
    twfRequire(
        wireguardCommonInit(&proof->client, encoded, &proof->client, (wireguard_callbacks_t) {.output = proofOutput}),
        "proof client initialization failed");
    cJSON *peer =
        cJSON_Parse("{\"publickey\":\"GnRcOavdc180YrXak138cZxWlMoEUZL0Mg/ZyWhLBgo=\",\"allowedips\":\"0.0.0.0/0\"}");
    uint8_t index;
    twfRequire(wireguardCommonAddConfiguredPeer(&proof->client, peer, &index), "proof client peer failed");
    cJSON_Delete(peer);
    proof->ingress = memoryAllocateZero(sizeof(ingress_t));
    mutexInit(&proof->ingress->lock);
    atomic_init(&proof->ingress->references, 1);
    twfRequire(ipaddr_aton("192.0.2.1", &proof->ingress->ip), "proof endpoint invalid");
    proof->ingress->port = 40000;
}
static void controlResponse(tunnel_t *auth, bool reject)
{
    authenticationclient_tstate_t *as = tunnelGetState(auth);
    as->max_pending_requests          = 8;
    twfRequire(authenticationclientPendingAppend(as, 99, kAuthenticationClientRequestTypeAuthenticate, 0),
               "control correlation setup failed");
    const char *body = reject ? "authentication-failed"
                              : "1111111111111111111111111111111111111111111111111111111111111111"
                                "2222222222222222222222222222222222222222222222222222222222222222";
    authenticationclientHandleResponseFrame(auth,
                                            NULL,
                                            reject ? kAuthenticationClientResponseTypeError
                                                   : kAuthenticationClientResponseTypeSession,
                                            99,
                                            (const uint8_t *) body,
                                            (uint32_t) strlen(body),
                                            0,
                                            0,
                                            0);
    twfRequire(as->auth_rejected == reject, "correlated control transition failed");
}
static node_t   authentication_node;
static unsigned opened_count, payload_count;
static void     fixturePayload(tunnel_t *sink, line_t *line, sbuf_t *packet)
{
    discard sink;
    twfRequire(lineGetCurrentUser(line)->user_id == 42, "existing payload lost its identity");
    ++payload_count;
    lineReuseBuffer(line, packet);
}
static void existingTraffic(server_t *state, line_t *line)
{
    sbuf_t *packet = bufferpoolGetSmallBuffer(lineGetBufferPool(line));
    sbufSetLength(packet, 19);
    sbufWriteZeros(packet, 19);
    tunnelNextUpStreamPayload(state->ptc, line, packet);
}
node_t *__wrap_nodemanagerGetConfigNodeByName(node_manager_config_t *config, const char *name);
node_t *__wrap_nodemanagerGetConfigNodeByName(node_manager_config_t *config, const char *name)
{
    discard config;
    discard name;
    return &authentication_node;
}
static void fixtureOwnedFinish(tunnel_t *owner, line_t *line)
{
    memoryZeroAligned32(lineGetState(line, owner), owner->lstate_size);
    lineDestroy(line);
}
static void fixtureOpened(tunnel_t *sink, line_t *line)
{
    discard sink;
    twfRequire(lineGetCurrentUser(line) != NULL &&
                   (lineHasAuthenticatedUsername(line, "account-a") || lineHasAuthenticatedUsername(line, "account-b")),
               "anonymous flow escaped the binding helper");
    ++opened_count;
}
static void fixtureFinished(tunnel_t *sink, line_t *line)
{
    discard sink;
    discard line;
}
static void closeFixtureLine(tunnel_t *owner, line_t *line)
{
    tunnelNextUpStreamFinish(owner, line);
    memoryZeroAligned32(lineGetState(line, owner), owner->lstate_size);
    lineDestroy(line);
    lineUnref(line);
}
static line_t *prepareFixtureLine(server_t *state, twf_line_pool_t *pool, unsigned binding, const char *source,
                                  bool datagram)
{
    line_t *line = twfLinePoolCreateLine(pool);
    lineRef(line);
    addresscontextSetIpAddressPortProtocol(lineGetSourceAddressContext(line), source, 40000, datagram ? 17 : 6);
    addresscontextSetIpAddressPortProtocol(
        lineGetDestinationAddressContext(line), "203.0.113.1", 443, datagram ? 17 : 6);
    ptc_lstate_t *metadata = lineGetState(line, state->ptc);
    metadata->kind         = datagram ? kPtcLineKindUdp : kPtcLineKindTcp;
    metadata->source_epoch = state->bindings[binding].epoch;
    return line;
}
static line_t *openFixtureLine(server_t *state, twf_line_pool_t *pool, unsigned binding, const char *source,
                               bool datagram)
{
    line_t *line = prepareFixtureLine(state, pool, binding, source, datagram);
    tunnelNextUpStreamInit(state->ptc, line);
    return line;
}
static void addAccount(users_t *users, uint64_t id, const char *password, const char *range, uint8_t key[32])
{
    user_t user;
    twfRequire(userCreate(&user, password), "account creation failed");
    userSetId(&user, id);
    twfRequire(userSetWireGuardAllowedIps(&user, range), "account range invalid");
    user.limit.ips      = 1;
    user.limit.cons_out = 3;
    memoryCopy(key, user.wireguard_publickey, 32);
    twfRequire(usersAddUser(users, &user), "account insert failed");
    twfRequire(usersSetUserName(users,
                                usersLookupByIdentifier(users, id),
                                id == 42   ? "account-a"
                                : id == 43 ? "account-b"
                                           : "account-c"),
               "account name failed");
    user_t *stored                             = usersLookupByIdentifier(users, id);
    stored->runtime.identity_generation_floor  = 3;
    stored->runtime.wireguard_generation_floor = 3;
    userDestroy(&user);
}
int main(void)
{
    testCaseSet("wireguard_user_binding_test");
    twfRequire(userTestRuntimeInitialize(), "crypto setup failed");
    twfRequire(createNetworkLogger(NULL, false) != NULL, "logger setup failed");
    twf_worker_env_t environment;
    twfWorkerEnvSetup(&environment, 8192, 32);
    users_t users;
    twfRequire(usersCreate(&users), "users setup failed");
    uint8_t keys[3][32];
    addAccount(&users, 42, "first-account", "10.50.0.4/30", keys[0]);
    addAccount(&users, 43, "second-account", "10.60.0.2/32", keys[1]);
    addAccount(&users, 44, "third-account", "10.70.0.2/32", keys[2]);
    tunnel_t                      *auth = tunnelCreate(NULL, sizeof(authenticationclient_tstate_t), 0);
    authenticationclient_tstate_t *as   = tunnelGetState(auth);
    mutexInit(&as->control_mutex);
    rwlockinit(&as->users_lock);
    as->traffic_multiplier = kUserTrafficMultiplierScale;
    as->users              = &users;
    as->started = as->users_loaded = as->clock_loaded = true;
    atomic_init(&as->users_generation, 7);
    authentication_node          = nodeAuthenticationClientGet();
    authentication_node.instance = auth;
    node_t    owner_node         = nodeWireGuardServerGet();
    tunnel_t *server             = tunnelCreate(&owner_node, sizeof(server_t), 0);
    server_t *state              = tunnelGetState(server);
    mutexInit(&state->bindings_lock);
    wireguardDispatchInit(&state->dispatch);
    state->tunnel               = server;
    state->auth                 = auth;
    state->connection           = true;
    state->receiving_generation = 7;
    twfRequire(wireguardCommonInit(&state->engine,
                                   "EBJOHctLU2w8uteyTE+WU0hruB09Ub0vwVS+Gt9wAls=",
                                   state,
                                   (wireguard_callbacks_t) {
                                       .candidate = candidate, .authenticated = authenticated, .output = proofOutput}),
               "engine setup failed");
    state->ptc                                   = tunnelCreate(NULL, 0, sizeof(ptc_lstate_t));
    state->ptc->fnFinD                           = fixtureOwnedFinish;
    state->binder                                = tunnelCreate(NULL, sizeof(server_t *), 0);
    *(server_t **) tunnelGetState(state->binder) = state;
    state->binder->fnInitU                       = bindingInit;
    node_t controller_node                       = nodeUserControllerGet();
    controller_node.node_settings_json           = cJSON_Parse("{\"auth-client-node-name\":\"accounts\"}");
    state->controller                            = controller_node.createHandle(&controller_node);
    twfRequire(state->controller != NULL, "controller setup failed");
    usercontrollerSetPayloadModeResolver(state->controller, server, payloadMode);
    state->controller->onPrepare(state->controller);
    tunnel_t *sink   = tunnelCreate(NULL, 0, 0);
    sink->fnInitU    = fixtureOpened;
    sink->fnFinU     = fixtureFinished;
    sink->fnPayloadU = fixturePayload;
    tunnelBind(state->ptc, state->binder);
    tunnelBind(state->binder, state->controller);
    tunnelBind(state->controller, sink);
    state->controller->lstate_offset = state->ptc->lstate_size;
    twf_line_pool_t pool;
    twfLinePoolSetup(&pool, state->ptc->lstate_size + state->controller->lstate_size, 16);
    state->receiving_generation = 2;
    twfRequire(candidate(state, keys[0]) == NULL && ! state->bindings[0].occupied,
               "queued handshake predating credential ownership published a binding");
    state->receiving_generation = 7;
    proof_t proofs[2];
    setupProof(&proofs[0], state, "first-account");
    setupProof(&proofs[1], state, "second-account");
    for (unsigned i = 0; i < 2; ++i)
    {
        exchangeProof(&proofs[i]);
        twfRequire(state->bindings[i].usable && state->engine.peers[i].curr_keypair.valid,
                   "real protocol proof did not publish binding");
    }
    line_t *a     = openFixtureLine(state, &pool, 0, "10.50.0.5", false);
    line_t *b     = openFixtureLine(state, &pool, 0, "10.50.0.5", true);
    line_t *other = openFixtureLine(state, &pool, 1, "10.60.0.2", true);
    twfRequire(opened_count == 3 && lineGetCurrentUser(a)->user_id == 42 && lineGetCurrentUser(other)->user_id == 43,
               "two accounts lost their independent inner-flow identities");
    atomicIncU64(&as->users_generation);
    twfRequire(candidate(state, keys[0]) == &state->engine.peers[0],
               "queued handshake lost continuous authorization across a full refresh");
    ip_addr_t continuous_source;
    twfRequire(ipaddr_aton("10.50.0.5", &continuous_source) &&
                   sourceEpoch(state, &continuous_source) == state->bindings[0].epoch,
               "unchanged full refresh revoked the source epoch of an active account");
    user_t *account = usersLookupByIdentifier(&users, 42);
    twfRequire(account->runtime.active_cons_out == 2 && account->runtime.ip_usage_count == 1,
               "same inner IP did not share its account IP slot");
    const uint64_t saved_epoch = state->bindings[0].epoch;
    line_t        *delayed_tcp = prepareFixtureLine(state, &pool, 0, "10.50.0.5", false);
    line_t        *delayed_udp = prepareFixtureLine(state, &pool, 0, "10.50.0.5", true);
    controlResponse(auth, true);
    twfRequire(! authenticationclientCanAuthenticate(auth) && sourceEpoch(state, &continuous_source) == saved_epoch &&
                   ! authenticationclientUserShouldClose(auth, lineGetCurrentUser(a), 0),
               "control rejection revoked an eligible established binding");
    line_t *blocked = delayed_tcp;
    tunnelNextUpStreamInit(state->ptc, blocked);
    twfRequire(! lineIsAlive(blocked) && opened_count == 3 && account->runtime.active_cons_out == 2,
               "delayed TCP Init bypassed rejection or disturbed old reservations");
    lineUnref(blocked);
    blocked = delayed_udp;
    tunnelNextUpStreamInit(state->ptc, blocked);
    twfRequire(! lineIsAlive(blocked) && opened_count == 3 && account->runtime.active_cons_out == 2,
               "UDP Init bypassed rejection or disturbed old reservations");
    lineUnref(blocked);
    const uint64_t before_traffic = account->stats.traffic.u;
    existingTraffic(state, a);
    existingTraffic(state, b);
    twfRequire(payload_count == 2 && account->stats.traffic.u == before_traffic + 38 && lineIsAlive(a) &&
                   lineIsAlive(b),
               "control rejection interrupted existing TCP/UDP accounting or delivery");
    twfRequire(candidate(state, keys[2]) == NULL, "new eligible peer bypassed control rejection");
    /* Crypto expiry does not erase the logical binding or prevent rekey. */
    keypairDestroy(&state->engine.peers[0].curr_keypair);
    keypairDestroy(&state->engine.peers[0].next_keypair);
    keypairDestroy(&state->engine.peers[0].prev_keypair);
    exchangeProof(&proofs[0]);
    twfRequire(state->bindings[0].usable && state->bindings[0].epoch == saved_epoch &&
                   state->engine.peers[0].curr_keypair.valid,
               "cached live binding could not rekey during control rejection");
    atomicIncU64(&as->users_generation);
    reconcile(state);
    twfRequire(state->bindings[0].usable && sourceEpoch(state, &continuous_source) == saved_epoch,
               "unchanged refresh during rejection retired existing flows");
    controlResponse(auth, false);
    twfRequire(authenticationclientCanAuthenticate(auth) && state->bindings[0].epoch == saved_epoch,
               "admission recovery changed a continuous epoch");
    line_t *denied = openFixtureLine(state, &pool, 0, "10.50.0.6", false);
    twfRequire(! lineIsAlive(denied) && opened_count == 3, "second inner IP bypassed its limit");
    lineUnref(denied);
    line_t *spoof = openFixtureLine(state, &pool, 1, "10.50.0.5", true);
    twfRequire(! lineIsAlive(spoof) && opened_count == 3, "peer acquired another account through source spoofing");
    lineUnref(spoof);
    closeFixtureLine(state->ptc, a);
    twfRequire(account->runtime.ip_usage_count == 1, "closing one flow released the shared IP slot");
    closeFixtureLine(state->ptc, b);
    twfRequire(account->runtime.ip_usage_count == 0 && account->runtime.active_cons_out == 0,
               "last flow leaked reservations");
    line_t *replacement = openFixtureLine(state, &pool, 0, "10.50.0.6", false);
    twfRequire(lineIsAlive(replacement) && opened_count == 4, "released IP slot was not reusable");
    closeFixtureLine(state->ptc, replacement);
    closeFixtureLine(state->ptc, other);
    twfRequire(usersSetUserEnabled(&users, account, false), "disable failed");
    denied = openFixtureLine(state, &pool, 0, "10.50.0.5", true);
    twfRequire(! lineIsAlive(denied) && opened_count == 4 && account->runtime.active_cons_out == 0,
               "disabled account admitted a flow or leaked a reservation");
    lineUnref(denied);
    twfRequire(usersSetUserEnabled(&users, account, true), "enable before retirement failed");
    clearBinding(state, 0);
    controlResponse(auth, true);
    twfRequire(candidate(state, keys[0]) == NULL && ! state->bindings[0].occupied,
               "retired binding resurrected during rejection");
    state->controller->onDestroy(state->controller, wwLifecycleStartupRollback());
    tunnelDestroy(state->ptc);
    tunnelDestroy(state->binder);
    tunnelDestroy(sink);
    for (unsigned i = 0; i < 2; ++i)
    {
        ingressRelease(state->bindings[i].ingress);
        authenticationclientWireGuardAuthorizationClear(&state->bindings[i].authorization);
        wireguardDeviceDestroy(&proofs[i].client);
        ingressRelease(proofs[i].ingress);
    }
    wireguardDeviceDestroy(&state->engine);
    mutexDestroy(&state->bindings_lock);
    tunnelDestroy(server);
    twfLinePoolTeardown(&pool);
    memoryFree(as->pending_requests);
    usersDestroy(&users);
    mutexDestroy(&as->control_mutex);
    rwlockDestroy(&as->users_lock);
    tunnelDestroy(auth);
    cJSON_Delete(controller_node.node_settings_json);
    memoryFree(controller_node.type);
    memoryFree(authentication_node.type);
    memoryFree(owner_node.type);
    twfWorkerEnvTeardown(&environment);
    networkloggerDestroy();
    userTestRuntimeCleanup();
    return 0;
}
