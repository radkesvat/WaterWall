#pragma once
#include "wwapi.h"

tunnel_t   *authTestPeerCreate(uint32_t offset);
void        authTestPeerDestroy(tunnel_t *server);
uint32_t    authTestPeerLineSize(void);
user_stat_t authTestPeerStats(tunnel_t *server, uint64_t id);
uint64_t    authTestPeerFirstUse(tunnel_t *server);
void        authTestPeerExpireSessions(tunnel_t *server);
void        authTestPeerLoseEpoch(tunnel_t *server, unsigned client);
void        authTestPeerPassword(tunnel_t *server);
void        authTestPeerPopulate(tunnel_t *server, unsigned count);
void        authTestPeerRemoveUser(tunnel_t *server);
uint64_t    authTestPeerSequence(tunnel_t *server, unsigned client);
void        authTestPeerCredentials(tunnel_t *server, unsigned client, uint8_t token[64], char epoch[65]);
size_t      authTestPeerPadUsersResponse(tunnel_t *server, size_t json_length);
void        authTestPeerPermissions(tunnel_t *server, unsigned client, bool user_write, bool stats_push);
void        authTestPeerSetUser(tunnel_t *server, uint64_t id, const user_update_t *update);
cJSON      *authTestPeerUserJson(tunnel_t *server, uint64_t id);
char       *authTestPeerSnapshot(tunnel_t *server);
void        authTestPeerInsertUser(tunnel_t *server, uint64_t id, const char *password);
cJSON      *authTestPeerApi(tunnel_t *server, const char *operation, const char *body, enum api_result_e expected);
void        authTestPeerSetConfigRevision(tunnel_t *server, uint64_t revision);
tunnel_t   *authTestControllerCreate(tunnel_t *auth);
line_t     *authTestControllerOpen(tunnel_t *controller, tunnel_chain_t *chain);
void        authTestControllerPayload(tunnel_t *controller, line_t *line);
void        authTestControllerSweep(tunnel_t *controller);
void        authTestControllerDestroy(tunnel_t *controller);
