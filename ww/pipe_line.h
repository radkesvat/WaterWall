#pragma once

#include "tunnel.h"
#include "ww.h"

/*

    pipeline helps you connect 2 lines that are not in the same thread/worker

    it manages the thread safety and efficiency

    i hope you don't use it, currently only used for halfduplex server since there were no other way...

*/

struct pipe_line_s
{
    bool           direct_mode;
    atomic_bool    closed;

    // thread local:
    tunnel_t *self;
    uint8_t   left_tid;
    uint8_t   right_tid;
    line_t   *left_line;
    line_t   *right_line;

    TunnelFlowRoutine local_up_stream;
    TunnelFlowRoutine local_down_stream;

};

typedef struct pipe_line_s pipe_line_t;

bool         writePipeLineLTR(pipe_line_t *p, context_t *c);
bool         writePipeLineRTL(pipe_line_t *p, context_t *c);
void         freePipeLine(pipe_line_t *p);
pipe_line_t *newPipeLine(uint8_t tid_left, tunnel_t *self, uint8_t tid_right);
