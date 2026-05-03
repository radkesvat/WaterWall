#pragma once

#include "wwapi.h"

typedef struct loggertunnel_tstate_s
{
    uint8_t  mode;
    uint8_t  output_mode;
    uint8_t  log_level;
    uint8_t  _padding0;
    uint64_t up_counter;
    uint64_t down_counter;
    char    *file_prefix;
    char    *up_path;
    char    *down_path;
    char    *all_path;
    wmutex_t file_mutex;
} loggertunnel_tstate_t;

enum
{
    kTunnelStateSize = sizeof(loggertunnel_tstate_t),
    kLineStateSize   = 0
};

enum loggertunnel_mode_e
{
    kLoggerTunnelModeLog = 0,
    kLoggerTunnelModeFile,
    kLoggerTunnelModeTcpPayloadFile
};

enum loggertunnel_output_mode_e
{
    kLoggerTunnelOutputModePerPayload = 0,
    kLoggerTunnelOutputModeSplitDirection,
    kLoggerTunnelOutputModeSingleFile
};

WW_EXPORT void         loggertunnelTunnelDestroy(tunnel_t *t);
WW_EXPORT tunnel_t    *loggertunnelTunnelCreate(node_t *node);
WW_EXPORT api_result_t loggertunnelTunnelApi(tunnel_t *instance, sbuf_t *message);

void loggertunnelTunnelUpStreamInit(tunnel_t *t, line_t *l);
void loggertunnelTunnelUpStreamEst(tunnel_t *t, line_t *l);
void loggertunnelTunnelUpStreamFinish(tunnel_t *t, line_t *l);
void loggertunnelTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void loggertunnelTunnelUpStreamPause(tunnel_t *t, line_t *l);
void loggertunnelTunnelUpStreamResume(tunnel_t *t, line_t *l);

void loggertunnelTunnelDownStreamInit(tunnel_t *t, line_t *l);
void loggertunnelTunnelDownStreamEst(tunnel_t *t, line_t *l);
void loggertunnelTunnelDownStreamFinish(tunnel_t *t, line_t *l);
void loggertunnelTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void loggertunnelTunnelDownStreamPause(tunnel_t *t, line_t *l);
void loggertunnelTunnelDownStreamResume(tunnel_t *t, line_t *l);

char *loggertunnelBuildStaticPath(const char *prefix, const char *suffix);
void  loggertunnelHandlePayload(tunnel_t *t, sbuf_t *buf, bool is_upstream);
