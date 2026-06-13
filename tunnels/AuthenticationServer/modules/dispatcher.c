#include "structure.h"

#include "loggers/network_logger.h"
#include "modules/add_new_user/add_new_user.h"
#include "modules/authenticate/authenticate.h"
#include "modules/get_all_users/get_all_users.h"
#include "modules/get_user_by_password/get_user_by_password.h"
#include "modules/get_user_by_sha256/get_user_by_sha256.h"
#include "modules/get_user_by_sha256_base64/get_user_by_sha256_base64.h"
#include "modules/get_user_by_sha256_hex/get_user_by_sha256_hex.h"
#include "modules/ping/ping.h"
#include "modules/push_user_stats/push_user_stats.h"
#include "modules/update_user/update_user.h"
#include "modules/update_user_trafic_stats_diff/update_user_trafic_stats_diff.h"

typedef struct authenticationserver_module_s
{
    uint8_t                                request_type;
    const char                            *name;
    authenticationserver_module_handler_fn handler;
    bool                                   public_access;
    bool                                   require_stats_push;
    bool                                   require_user_pull;
    bool                                   require_user_write;
} authenticationserver_module_t;

static const authenticationserver_module_t kAuthenticationServerModules[] = {
    {
        .request_type  = kAuthenticationServerRequestTypeAuthenticate,
        .name          = "Authenticate",
        .handler       = authenticationserverAuthenticateHandle,
        .public_access = true,
    },
    {
        .request_type = kAuthenticationServerRequestTypePing,
        .name         = "ping",
        .handler      = authenticationserverPingHandle,
    },
    {
        .request_type      = kAuthenticationServerRequestTypeGetUserBySHA256Hex,
        .name              = "GetUserBySHA256Hex",
        .handler           = authenticationserverGetUserBySHA256HexHandle,
        .require_user_pull = true,
    },
    {
        .request_type      = kAuthenticationServerRequestTypeGetUserBySHA256Base64,
        .name              = "GetUserBySHA256Base64",
        .handler           = authenticationserverGetUserBySHA256Base64Handle,
        .require_user_pull = true,
    },
    {
        .request_type      = kAuthenticationServerRequestTypeGetUserBySHA256,
        .name              = "GetUserBySHA256",
        .handler           = authenticationserverGetUserBySHA256Handle,
        .require_user_pull = true,
    },
    {
        .request_type      = kAuthenticationServerRequestTypeGetUserByPassword,
        .name              = "GetUserByPassword",
        .handler           = authenticationserverGetUserByPasswordHandle,
        .require_user_pull = true,
    },
    {
        .request_type       = kAuthenticationServerRequestTypeAddNewUser,
        .name               = "AddNewUser",
        .handler            = authenticationserverAddNewUserHandle,
        .require_user_write = true,
    },
    {
        .request_type       = kAuthenticationServerRequestTypeUpdateUser,
        .name               = "UpdateUser",
        .handler            = authenticationserverUpdateUserHandle,
        .require_user_write = true,
    },
    {
        .request_type       = kAuthenticationServerRequestTypeUpdateUserTraficStatsDiff,
        .name               = "UpdateUserTraficStatsDiff",
        .handler            = authenticationserverUpdateUserTraficStatsDiffHandle,
        .require_stats_push = true,
    },
    {
        .request_type      = kAuthenticationServerRequestTypeGetAllUsers,
        .name              = "GetAllUsers",
        .handler           = authenticationserverGetAllUsersHandle,
        .require_user_pull = true,
    },
    {
        .request_type       = kAuthenticationServerRequestTypePushUserStats,
        .name               = "PushUserStats",
        .handler            = authenticationserverPushUserStatsHandle,
        .require_stats_push = true,
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

sbuf_t *authenticationserverDispatchRequest(uint8_t       request_type,
                                            const uint8_t correlation_id[kAuthenticationServerCorrelationIdSize],
                                            tunnel_t *t, line_t *l, authenticationserver_session_t *session,
                                            const uint8_t *request_data, uint32_t request_data_len)
{
    const authenticationserver_module_t *module = authenticationserverFindModule(request_type);
    if (LIKELY(module != NULL))
    {
        if (LIKELY(! module->public_access))
        {
            if (UNLIKELY(session == NULL))
            {
                LOGW("AuthenticationServer: rejected request type %u without a valid session token",
                     (unsigned int) request_type);
                return authenticationserverCreateErrorResponseFrame(l, correlation_id, "authentication-required");
            }
            if (UNLIKELY(module->require_stats_push && ! session->allow_stats_push))
            {
                return authenticationserverCreateErrorResponseFrame(l, correlation_id, "stats-push-not-allowed");
            }
            if (UNLIKELY(module->require_user_pull && ! session->allow_user_pull))
            {
                return authenticationserverCreateErrorResponseFrame(l, correlation_id, "user-pull-not-allowed");
            }
            if (UNLIKELY(module->require_user_write && ! session->allow_user_write))
            {
                return authenticationserverCreateErrorResponseFrame(l, correlation_id, "user-write-not-allowed");
            }
        }

        LOGD("AuthenticationServer: dispatching %u-byte request to %s module",
             (unsigned int) request_data_len,
             module->name);
        return module->handler(correlation_id, t, l, session, request_data, request_data_len);
    }

    LOGW("AuthenticationServer: unknown request type %u", (unsigned int) request_type);
    return authenticationserverCreateErrorResponseFrame(l, correlation_id, "unknown-request-type");
}
