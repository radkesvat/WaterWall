#include "adapter.h"
#include "line.h"
#include "loggers/internal_logger.h"
#include "managers/node_manager.h"
#include "node.h"

void adapterDefaultOnChainUpEnd(tunnel_t *t, tunnel_chain_t *tc)
{
    tunnelchainInsert(tc, t);
}

void adapterDefaultOnChainDownEnd(tunnel_t *t, tunnel_chain_t *tc)
{
    tunnelDefaultOnChain(t, tc);
}

void adapterDefaultOnIndexUpEnd(tunnel_t *t, tunnel_array_t *arr, uint16_t *index, uint16_t *mem_offset)
{
    tunnelarrayInsert(arr, t);
    t->chain_index   = *index;
    t->lstate_offset = *mem_offset;
    (*index)++;
    *mem_offset += t->lstate_size;
    assert(t->next == NULL);
}

void adapterDefaultOnIndexDownEnd(tunnel_t *t, tunnel_array_t *arr, uint16_t *index, uint16_t *mem_offset)
{
    tunnelarrayInsert(arr, t);
    t->chain_index   = *index;
    t->lstate_offset = *mem_offset;
    (*index)++;
    *mem_offset += t->lstate_size;
    if (t->next)
    {

        t->next->onIndex(t->next, arr, index, mem_offset);
    }
}

static void illegalPauseResume(tunnel_t *t, line_t *line)
{
    (void) line;
    LOGF("Illegal call to pause/resume on %s", t->node->name);
    exit(1);
}

tunnel_t *adapterCreate(node_t *node, uint16_t tstate_size, uint16_t lstate_size, bool up_end)
{
    tunnel_t *t = tunnelCreate(node, tstate_size, lstate_size);

    if (up_end)
    {
        t->onChain   = adapterDefaultOnChainUpEnd;
        t->onIndex   = adapterDefaultOnIndexUpEnd;
        t->fnPauseD  = illegalPauseResume;
        t->fnResumeD = illegalPauseResume;
    }
    else
    {
        t->onChain = adapterDefaultOnChainDownEnd;
        t->onIndex = adapterDefaultOnIndexDownEnd;

        t->fnPauseU  = illegalPauseResume;
        t->fnResumeU = illegalPauseResume;
    }
    return t;
}
