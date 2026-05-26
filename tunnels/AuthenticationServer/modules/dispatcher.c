#include "structure.h"

#include "loggers/network_logger.h"
#include "modules/add_new_user/add_new_user.h"
#include "modules/get_all_users/get_all_users.h"
#include "modules/get_user_by_password/get_user_by_password.h"
#include "modules/get_user_by_sha256/get_user_by_sha256.h"
#include "modules/get_user_by_sha256_base64/get_user_by_sha256_base64.h"
#include "modules/get_user_by_sha256_hex/get_user_by_sha256_hex.h"
#include "modules/ping/ping.h"
#include "modules/pull_changes_sync/pull_changes_sync.h"
#include "modules/update_user/update_user.h"
#include "modules/update_user_trafic_stats_diff/update_user_trafic_stats_diff.h"

typedef struct authenticationserver_module_s
{
    uint8_t                                request_type;
    const char                            *name;
    authenticationserver_module_handler_fn  handler;
    bool                                   returns_user_state;
    bool                                   bumps_sync_index;
} authenticationserver_module_t;

static const authenticationserver_module_t kAuthenticationServerModules[] = {
    {
        .request_type = kAuthenticationServerRequestTypePing,
        .name         = "ping",
        .handler      = authenticationserverPingHandle,
    },
    {
        .request_type = kAuthenticationServerRequestTypeGetUserBySHA256Hex,
        .name         = "GetUserBySHA256Hex",
        .handler      = authenticationserverGetUserBySHA256HexHandle,
        .returns_user_state = true,
    },
    {
        .request_type = kAuthenticationServerRequestTypeGetUserBySHA256Base64,
        .name         = "GetUserBySHA256Base64",
        .handler      = authenticationserverGetUserBySHA256Base64Handle,
        .returns_user_state = true,
    },
    {
        .request_type = kAuthenticationServerRequestTypeGetUserBySHA256,
        .name         = "GetUserBySHA256",
        .handler      = authenticationserverGetUserBySHA256Handle,
        .returns_user_state = true,
    },
    {
        .request_type = kAuthenticationServerRequestTypeGetUserByPassword,
        .name         = "GetUserByPassword",
        .handler      = authenticationserverGetUserByPasswordHandle,
        .returns_user_state = true,
    },
    {
        .request_type = kAuthenticationServerRequestTypeAddNewUser,
        .name         = "AddNewUser",
        .handler      = authenticationserverAddNewUserHandle,
        .bumps_sync_index = true,
    },
    {
        .request_type = kAuthenticationServerRequestTypeUpdateUser,
        .name         = "UpdateUser",
        .handler      = authenticationserverUpdateUserHandle,
        .bumps_sync_index = true,
    },
    {
        .request_type = kAuthenticationServerRequestTypeUpdateUserTraficStatsDiff,
        .name         = "UpdateUserTraficStatsDiff",
        .handler      = authenticationserverUpdateUserTraficStatsDiffHandle,
    },
    {
        .request_type = kAuthenticationServerRequestTypeGetAllUsers,
        .name         = "GetAllUsers",
        .handler      = authenticationserverGetAllUsersHandle,
        .returns_user_state = true,
    },
    {
        .request_type = kAuthenticationServerRequestTypePullChangesSync,
        .name         = "PullChangesSync",
        .handler      = authenticationserverPullChangesSyncHandle,
        .returns_user_state = true,
    },
};

static const authenticationserver_module_t *authenticationserverFindModule(uint8_t request_type)
{
    for (uint32_t i = 0; i < sizeof(kAuthenticationServerModules) / sizeof(kAuthenticationServerModules[0]); ++i)
    {
        if (kAuthenticationServerModules[i].request_type == request_type)
        {
            return &kAuthenticationServerModules[i];
        }
    }

    return NULL;
}

sbuf_t *authenticationserverDispatchRequest(
    uint8_t       request_type,
    const uint8_t correlation_id[kAuthenticationServerCorrelationIdSize],
    tunnel_t     *t,
    line_t       *l,
    const uint8_t *request_data,
    uint32_t      request_data_len)
{
    const authenticationserver_module_t *module = authenticationserverFindModule(request_type);
    if (module != NULL)
    {
        LOGD("AuthenticationServer: dispatching %u-byte request to %s module",
             (unsigned int) request_data_len, module->name);
        return module->handler(correlation_id, t, l, request_data, request_data_len);
    }

    LOGW("AuthenticationServer: unknown request type %u", (unsigned int) request_type);
    return authenticationserverCreateErrorResponseFrame(l, correlation_id, "unknown-request-type");
}

bool authenticationserverRequestTypeReturnsUserState(uint8_t request_type)
{
    const authenticationserver_module_t *module = authenticationserverFindModule(request_type);
    return module != NULL && module->returns_user_state;
}

bool authenticationserverRequestTypeBumpsSyncIndex(uint8_t request_type)
{
    const authenticationserver_module_t *module = authenticationserverFindModule(request_type);
    return module != NULL && module->bumps_sync_index;
}
