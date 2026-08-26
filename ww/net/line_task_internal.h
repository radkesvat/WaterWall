#pragma once

/* Private pooled record captured by the public line-task scheduling family. */

#include "line.h"

typedef union line_task_callback_u {
    LineTaskFnNoBuf   no_buf;
    LineTaskFnWithBuf with_buf;
} line_task_callback_t;

typedef struct line_task_msg_s
{
    line_task_callback_t callback;
    LineTaskCancelFn     on_cancel;
    tunnel_t            *tunnel;
    line_t              *line;
    sbuf_t              *buf;
} line_task_msg_t;
