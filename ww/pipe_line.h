#pragma once

#include "hmutex.h"
#include "tunnel.h"

/*

    pipeline helps you connect 2 lines that are not in the same thread/worker

    it manages the thread safety and efficiency

    pipe dose not require free call, it automatically gets freed after both lines are finished

    sending a fin context to pipe will make it quiet, it will not send anything back even the queued items

    i hope you don't use it, currently only used for halfduplex server since there were no other way...

*/
struct pipe_line_s;

typedef void (*PipeLineFlowRoutine)(struct tunnel_s *, struct context_s *,struct pipe_line_s*pl);

struct pipe_line_s
{
    atomic_bool closed;
    atomic_int  refc;

    // thread local:
    tunnel_t *self;
    uint8_t   left_tid;
    uint8_t   right_tid;
    line_t   *left_line;
    line_t   *right_line;

    PipeLineFlowRoutine local_up_stream;
    PipeLineFlowRoutine local_down_stream;
};

typedef struct pipe_line_s pipe_line_t;

bool writePipeLineLTR(pipe_line_t *pl, context_t *c);
bool writePipeLineRTL(pipe_line_t *pl, context_t *c);

void newPipeLine(pipe_line_t **result, tunnel_t *self, uint8_t tid_left, line_t *left_line, uint8_t tid_right,
                PipeLineFlowRoutine local_up_stream, PipeLineFlowRoutine local_down_stream);
