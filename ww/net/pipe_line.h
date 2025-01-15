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

    i hope you don't use it, currently only used for halfduplex,reverse server since there were no other way...


    -- valgrind unfriendly, since we required 64byte alignment, so it says "possibly/definitely lost"
       but the pointer is saved in "memptr" field inside the object

*/

struct pipe_line_s;

typedef void (*PipeLineFlowRoutine)(tunnel_t *, struct context_s *, struct pipe_line_s *pl);

typedef struct pipe_line_s pipe_line_t;

pool_item_t *allocPipeLineMsgPoolHandle(generic_pool_t *pool);
void         destroyPipeLineMsgPoolHandle(generic_pool_t *pool, pool_item_t *item);

void pipeUpStreamInit(tunnel_t *self, line_t *line);
void pipeUpStreamEst(tunnel_t *self, line_t *line);
void pipeUpStreamFin(tunnel_t *self, line_t *line);
void pipeUpStreamPayload(tunnel_t *self, line_t *line, sbuf_t *payload);
void pipeUpStreamPause(tunnel_t *self, line_t *line);
void pipeUpStreamResume(tunnel_t *self, line_t *line);

void pipeOnUpLinePaused(void *state);
void pipeOnUpLineResumed(void *state);
void pipeOnDownLineResumed(void *state);
void pipeOnDownLinePaused(void *state);
bool pipeSendToUpStream(pipe_line_t *pl, context_t *c);
bool pipeSendToDownStream(pipe_line_t *pl, context_t *c);

void      pipeTo(tunnel_t *t, line_t *l, tid_t tid);
tunnel_t *newPipeTunnel(tunnel_t *t);
