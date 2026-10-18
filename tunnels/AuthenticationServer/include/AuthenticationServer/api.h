#pragma once

#include "api/node_api.h"
#include "structure.h"

enum
{
    kAuthenticationServerApiRequestCap = 4096,
    kAuthenticationServerApiBodyCap    = 256 * 1024,
    /* Includes bounded renderer/call stack and scalar snapshots. Parser storage
     * is charged separately, and is gone before snapshots are allocated. */
    kAuthenticationServerApiScratchCharge = 2048
};

typedef enum authenticationserver_api_kind_e
{
    kAuthenticationServerApiStatus,
    kAuthenticationServerApiGetUser,
    kAuthenticationServerApiListUsers
} authenticationserver_api_kind_t;

typedef struct authenticationserver_api_request_s
{
    uint64_t id, revision, position;
    uint8_t  instance_id[16];
    size_t   limit;
    bool     has_cursor;
} authenticationserver_api_request_t;

typedef struct authenticationserver_user_view_s
{
    uint64_t             config_revision, stats_revision, accounting_time_ms;
    uint8_t              instance_id[16];
    user_public_detail_t user;
} authenticationserver_user_view_t;

typedef struct authenticationserver_page_view_s
{
    uint64_t               config_revision, stats_revision, accounting_time_ms;
    uint8_t                instance_id[16];
    size_t                 position, count, total;
    user_public_summary_t *users;
} authenticationserver_page_view_t;

typedef struct authenticationserver_json_writer_s
{
    char    *output;
    size_t   used, capacity;
    uint64_t deadline_ms;
    bool     overflow, timeout;
} authenticationserver_json_writer_t;

typedef void (*authenticationserver_api_render_fn)(authenticationserver_json_writer_t *, const void *);

bool        authenticationserverRegisterApi(tunnel_t *t);
bool        authenticationserverApiExpired(uint64_t deadline_ms);
const char *authenticationserverApiParse(sbuf_t *message, const node_api_call_context_t *context,
                                         authenticationserver_api_kind_t     kind,
                                         authenticationserver_api_request_t *request);
const char *authenticationserverApiPublicError(user_public_result_t result);
const char *authenticationserverCopyUserView(tunnel_t *t, uint64_t id, size_t allowance, uint64_t deadline_ms,
                                             authenticationserver_user_view_t *view);
const char *authenticationserverCopyPageView(tunnel_t *t, const authenticationserver_api_request_t *request,
                                             size_t allowance, uint64_t deadline_ms,
                                             authenticationserver_page_view_t *view);

void authenticationserverJsonText(authenticationserver_json_writer_t *writer, const char *text);
void authenticationserverJsonString(authenticationserver_json_writer_t *writer, const char *text);
void authenticationserverJsonU64(authenticationserver_json_writer_t *writer, uint64_t value);
void authenticationserverApiCursor(const authenticationserver_page_view_t *view, size_t emitted, char cursor[65]);
api_result_t authenticationserverApiError(const node_api_call_context_t *context, const char *code);
api_result_t authenticationserverApiRender(const node_api_call_context_t *context, size_t body_cap,
                                           size_t retained_charge, authenticationserver_api_render_fn render,
                                           const void *view);

api_result_t authenticationserverApiStatus(tunnel_t *, sbuf_t *, const node_api_call_context_t *);
api_result_t authenticationserverApiGetUser(tunnel_t *, sbuf_t *, const node_api_call_context_t *);
api_result_t authenticationserverApiListUsers(tunnel_t *, sbuf_t *, const node_api_call_context_t *);
api_result_t authenticationserverApiUpdateUser(tunnel_t *, sbuf_t *, const node_api_call_context_t *);
api_result_t authenticationserverApiCreateUser(tunnel_t *, sbuf_t *, const node_api_call_context_t *);
