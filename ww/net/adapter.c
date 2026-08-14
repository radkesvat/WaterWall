#include "adapter.h"

/*
 * Implements adapter tunnel defaults for chain edges and blocked routines.
 */

#include "line.h"
#include "loggers/internal_logger.h"
#include "managers/node_manager.h"

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
    abortProgramNow(1);
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
    abortProgramNow(1);
}

tunnel_t *adapterCreate(node_t *node, size_t tstate_size, size_t lstate_size, adapter_edge_t edge)
{
    tunnel_t *t = tunnelCreate(node, tstate_size, lstate_size);

    // tunnelCreate() is nullable by contract: it returns NULL on a state-size
    // overflow or an allocation failure. Callers unwind from a NULL create
    // handle, so the failure has to survive as far as them.
    if (! t)
    {
        return NULL;
    }

    switch (edge)
    {
    case kAdapterChainHead:
        t->fnPauseU   = disabledRoutine;
        t->fnResumeU  = disabledRoutine;
        t->fnInitU    = disabledRoutine;
        t->fnEstU     = disabledRoutine;
        t->fnFinU     = disabledRoutine;
        t->fnPayloadU = disabledPayloadRoutine;
        break;

    case kAdapterChainEnd:
        t->fnPauseD   = disabledRoutine;
        t->fnResumeD  = disabledRoutine;
        t->fnInitD    = disabledRoutine;
        t->fnEstD     = disabledRoutine;
        t->fnFinD     = disabledRoutine;
        t->fnPayloadD = disabledPayloadRoutine;
        break;

    default:
        LOGF("adapterCreate received invalid edge value %d", (int) edge);
        abortProgramNow(1);
    }

    return t;
}
