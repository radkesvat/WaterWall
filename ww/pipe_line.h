#pragma once

#include "tunnel.h"

/*

    
    <---------------  Down Line  ------------------>
    
    ----------------------------|------------------|
               <- con ->           Pipe 1 thread 1 |
    ----------------------------|------------------|



    <----------------  Up Line   ------------------>

    |------------------|----------------------------
    |  Pipe 1 thread 2              <- con ->
    |------------------|----------------------------


    pipeline helps you connect 2 lines that are not in the same thread/worker

    it manages the thread safety and efficiency

    pipe dose not require free call, it automatically gets freed after both lines are finished

    payload is not copied, it is moved

    sending a fin context to pipe will make it quiet, it will not send anything back even the queued items
    will be destroyed on the destination thread

    i hope you don't use it, currently only used for halfduplex server since there were no other way...

    -- valgrind unfriendly, since we required 64byte alignment, so it says "possibly lost"
       but the pointer is saved in "memptr" field inside the object

*/

struct pipe_line_s;

typedef void (*PipeLineFlowRoutine)(struct tunnel_s *, struct context_s *, struct pipe_line_s *pl);

typedef struct pipe_line_s pipe_line_t;

pool_item_t *allocPipeLineMsgPoolHandle(struct generic_pool_s *pool);
void         destroyPipeLineMsgPoolHandle(struct generic_pool_s *pool, pool_item_t *item);

void pipeOnUpLinePaused(void *state);
void pipeOnUpLineResumed(void *state);
void pipeOnDownLineResumed(void *state);
void pipeOnDownLinePaused(void *state);

bool pipeUpStream(pipe_line_t *pl, context_t *c);
bool pipeDownStream(pipe_line_t *pl, context_t *c);

void newPipeLine(pipe_line_t **result, tunnel_t *self, uint8_t this_tid, line_t *left_line, uint8_t dest_tid,
                 PipeLineFlowRoutine local_up_stream, PipeLineFlowRoutine local_down_stream);
