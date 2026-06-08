#include "structure.h"

#include "loggers/network_logger.h"

void tcpconnectorLinestateInitialize(tcpconnector_lstate_t *ls)
{
    ls->pause_queue       = bufferqueueCreate(kPauseQueueCapacity);
    ls->io                = NULL;
    ls->idle_handle       = NULL;
    ls->dns_request       = NULL;
    ls->role              = kTcpConnectorLineRoleNormal;
    ls->destination_index = kTcpConnectorNoDestinationIndex;
    ls->connect_start_ms  = 0;
    ls->connected         = false;
    ls->race_attempts     = NULL;
    ls->race_attempt_count = 0;
    ls->race_open_attempts = 0;
    ls->race_completed    = false;
    ls->write_paused      = false;
    ls->read_paused       = false;
    ls->resolving         = false;
}

void tcpconnectorCancelDnsRequest(tcpconnector_lstate_t *ls)
{
    if (ls->dns_request != NULL)
    {
        ls->dns_request->cancelled = true;
        ls->dns_request            = NULL;
    }
    ls->resolving = false;
}

static void tcpconnectorRaceAttemptDestroy(tcpconnector_race_attempt_t *attempt)
{
    if (attempt == NULL)
    {
        return;
    }

    attempt->cancelled = true;
    if (attempt->io != NULL)
    {
        weventSetUserData(attempt->io, NULL);
        wioClose(attempt->io);
        attempt->io = NULL;
    }
    addresscontextReset(&attempt->dest_ctx);
    memoryFree(attempt);
}

static void tcpconnectorDestroyRaceAttempts(tcpconnector_lstate_t *ls)
{
    if (ls->race_attempts == NULL)
    {
        return;
    }

    for (uint32_t i = 0; i < ls->race_attempt_count; ++i)
    {
        tcpconnectorRaceAttemptDestroy(ls->race_attempts[i]);
    }

    memoryFree(ls->race_attempts);
    ls->race_attempts      = NULL;
    ls->race_attempt_count = 0;
    ls->race_open_attempts = 0;
}

void tcpconnectorLinestateDestroy(tcpconnector_lstate_t *ls)
{
    tcpconnectorCancelDnsRequest(ls);
    tcpconnectorDestroyRaceAttempts(ls);
    bufferqueueDestroy(&ls->pause_queue);
    if (ls->idle_handle)
    {
        LOGF("TcpConnector: idle item still exists for FD:%x ", wioGetFD(ls->io));
        terminateProgram(1);
    }
    memoryZeroAligned32(ls, tunnelGetCorrectAlignedLineStateSize(sizeof(tcpconnector_lstate_t)));
}
