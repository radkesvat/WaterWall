#include "structure.h"

#include "loggers/network_logger.h"

bool connectionfisherclientLinestateInitializeMain(connectionfisherclient_lstate_t *ls, line_t *l, uint32_t child_count)
{
    discard l;

    *ls = (connectionfisherclient_lstate_t) {
        .role               = kConnectionFisherClientRoleMain,
        .main_est_forwarded = false,
        .open_child_count   = 0,
        .selected_child     = NULL,
        .main_line          = NULL,
        .pending_up         = bufferqueueCreate(kConnectionFisherPendingQueueCap),
    };

    if (child_count == 0)
    {
        return true;
    }

#if WW_COMPILE_FOR_32BIT
    if (UNLIKELY(child_count > SIZE_MAX / sizeof(*ls->child_lines)))
    {
        LOGW("ConnectionFisherClient: child line count is too large to represent");
        return false;
    }
#endif

    ls->child_lines = memoryAllocateZero(sizeof(*ls->child_lines) * (size_t) child_count);
    if (UNLIKELY(ls->child_lines == NULL))
    {
        LOGW("ConnectionFisherClient: failed to allocate child line slots");
        return false;
    }

    ls->child_count = child_count;
    return true;
}

void connectionfisherclientLinestateInitializeChild(connectionfisherclient_lstate_t *ls, line_t *l, line_t *main_l,
                                                    uint32_t slot)
{
    lineLock(main_l);

    *ls = (connectionfisherclient_lstate_t) {
        .role                     = kConnectionFisherClientRoleChild,
        .child_handshake_complete = false,
        .child_slot               = slot,
        .main_line                = main_l,
        .read_stream              = bufferstreamCreate(lineGetBufferPool(l), 0),
    };
}

void connectionfisherclientLinestateDestroyMain(connectionfisherclient_lstate_t *ls)
{
    if (ls->role != kConnectionFisherClientRoleMain)
    {
        return;
    }

    bufferqueueDestroy(&ls->pending_up);
    if (ls->child_lines != NULL)
    {
        memoryFree(ls->child_lines);
    }
    memoryZeroAligned32(ls, tunnelGetCorrectAlignedLineStateSize(sizeof(*ls)));
}

void connectionfisherclientLinestateDestroyChild(connectionfisherclient_lstate_t *ls)
{
    if (ls->role != kConnectionFisherClientRoleChild)
    {
        return;
    }

    bufferstreamDestroy(&ls->read_stream);
    memoryZeroAligned32(ls, tunnelGetCorrectAlignedLineStateSize(sizeof(*ls)));
}
