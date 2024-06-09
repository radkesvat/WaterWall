#pragma once

#include "hmutex.h"
#include "tunnel.h"

/*

    pipeline helps you connect 2 lines that are not in the same thread/worker

    it manages the thread safety and efficiency

    pipe dose not require free call, it automatically gets freed after both lines are finished

    sending a fin context to pipe will make it quiet, it will not send anything back even the queued items
    will be destroyed on the target thread

    i hope you don't use it, currently only used for halfduplex server since there were no other way...

*/

struct pipe_line_s;

typedef void (*PipeLineFlowRoutine)(struct tunnel_s *, struct context_s *,struct pipe_line_s*pl);



typedef struct pipe_line_s pipe_line_t;

bool pipeUpStream(pipe_line_t *pl, context_t *c);
bool pipeDownStream(pipe_line_t *pl, context_t *c);

void newPipeLine(pipe_line_t **result, tunnel_t *self, uint8_t tid_left, line_t *left_line, uint8_t tid_right,
                PipeLineFlowRoutine local_up_stream, PipeLineFlowRoutine local_down_stream);
