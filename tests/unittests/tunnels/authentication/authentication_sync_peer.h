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
