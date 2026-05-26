#include "structure.h"

#include "loggers/network_logger.h"
#include "modules/add_new_user/add_new_user.h"
#include "modules/get_user_by_password/get_user_by_password.h"
#include "modules/get_user_by_sha256/get_user_by_sha256.h"
#include "modules/get_user_by_sha256_base64/get_user_by_sha256_base64.h"
#include "modules/get_user_by_sha256_hex/get_user_by_sha256_hex.h"
#include "modules/ping/ping.h"
#include "modules/update_user/update_user.h"

typedef struct authenticationserver_module_s
{
    uint8_t                                request_type;
    const char                            *name;
    authenticationserver_module_handler_fn  handler;
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
    },
    {
        .request_type = kAuthenticationServerRequestTypeGetUserBySHA256Base64,
        .name         = "GetUserBySHA256Base64",
        .handler      = authenticationserverGetUserBySHA256Base64Handle,
    },
    {
        .request_type = kAuthenticationServerRequestTypeGetUserBySHA256,
        .name         = "GetUserBySHA256",
        .handler      = authenticationserverGetUserBySHA256Handle,
    },
    {
        .request_type = kAuthenticationServerRequestTypeGetUserByPassword,
        .name         = "GetUserByPassword",
        .handler      = authenticationserverGetUserByPasswordHandle,
    },
    {
        .request_type = kAuthenticationServerRequestTypeAddNewUser,
        .name         = "AddNewUser",
        .handler      = authenticationserverAddNewUserHandle,
    },
    {
        .request_type = kAuthenticationServerRequestTypeUpdateUser,
        .name         = "UpdateUser",
        .handler      = authenticationserverUpdateUserHandle,
    },
};

sbuf_t *authenticationserverDispatchRequest(
    uint8_t       request_type,
    const uint8_t correlation_id[kAuthenticationServerCorrelationIdSize],
    tunnel_t     *t,
    line_t       *l,
    const uint8_t *request_data,
    uint32_t      request_data_len)
{
    for (uint32_t i = 0; i < sizeof(kAuthenticationServerModules) / sizeof(kAuthenticationServerModules[0]); ++i)
    {
        const authenticationserver_module_t *module = &kAuthenticationServerModules[i];
        if (module->request_type == request_type)
        {
            LOGD("AuthenticationServer: dispatching %u-byte request to %s module",
                 (unsigned int) request_data_len, module->name);
            return module->handler(correlation_id, t, l, request_data, request_data_len);
        }
    }

    LOGW("AuthenticationServer: unknown request type %u", (unsigned int) request_type);
    return authenticationserverCreateErrorResponseFrame(l, correlation_id, "unknown-request-type");
}
