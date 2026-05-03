#include "adapter.h"

/*
 * Implements adapter tunnel defaults for chain edges and blocked routines.
 */

#include "line.h"
#include "loggers/internal_logger.h"
#include "managers/node_manager.h"

void adapterDefaultOnChainUpEnd(tunnel_t *t, tunnel_chain_t *tc)
{
    tunnelDefaultOnChain(t, tc);
}

void adapterDefaultOnChainDownEnd(tunnel_t *t, tunnel_chain_t *tc)
{
    tunnelDefaultOnChain(t, tc);
}

void adapterDefaultOnIndexUpEnd(tunnel_t *t, uint16_t index, uint16_t *mem_offset)
{
    t->chain_index   = index;
    t->lstate_offset = *mem_offset;
    *mem_offset += t->lstate_size;
}

void adapterDefaultOnIndexDownEnd(tunnel_t *t, uint16_t index, uint16_t *mem_offset)
{
    t->chain_index   = index;
    t->lstate_offset = *mem_offset;
    *mem_offset += t->lstate_size;
}

/**
 * @brief Guard routine used to block invalid payload calls on adapters.
 *
 * @param t Adapter tunnel.
 * @param line Line instance.
 * @param payload Payload argument.
 */
static void disabledPayloadRoutine(tunnel_t *t, line_t *line, sbuf_t *payload)
{
    discard t;
    discard line;
    discard payload;
    LOGF("Illegal call to payload routine on Adapter %s", t->node->name);
    assert(false); // print stack trace in debug mode, and terminate in release mode
    terminateProgram(1);
}

/**
 * @brief Guard routine used to block invalid non-payload calls on adapters.
 *
 * @param t Adapter tunnel.
 * @param line Line instance.
 */
static void disabledRoutine(tunnel_t *t, line_t *line)
{
    discard t;
    discard line;
    LOGF("Illegal call to routine on Adapter %s", t->node->name);
    assert(false); // print stack trace in debug mode, and terminate in release mode
    terminateProgram(1);
}

tunnel_t *adapterCreate(node_t *node, uint16_t tstate_size, uint16_t lstate_size, bool up_end)
{
    tunnel_t *t = tunnelCreate(node, tstate_size, lstate_size);

    if (up_end)
    {
        t->onChain = adapterDefaultOnChainUpEnd;
        t->onIndex = adapterDefaultOnIndexUpEnd;

        t->fnPauseD   = disabledRoutine;
        t->fnResumeD  = disabledRoutine;
        t->fnInitD    = disabledRoutine;
        t->fnEstD     = disabledRoutine;
        t->fnFinD     = disabledRoutine;
        t->fnPayloadD = disabledPayloadRoutine;
    }
    else
    {
        t->onChain = adapterDefaultOnChainDownEnd;
        t->onIndex = adapterDefaultOnIndexDownEnd;

        t->fnPauseU   = disabledRoutine;
        t->fnResumeU  = disabledRoutine;
        t->fnInitU    = disabledRoutine;
        t->fnEstU     = disabledRoutine;
        t->fnFinU     = disabledRoutine;
        t->fnPayloadU = disabledPayloadRoutine;
    }
    return t;
}
