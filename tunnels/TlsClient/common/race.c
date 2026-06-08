#include "race.h"
#include "sni_pool.h"

#include "loggers/network_logger.h"

bool tlsclientRaceIsEnabled(const tlsclient_tstate_t *ts)
{
    return ts->sni_selection == kTlsClientSniSelectionRace;
}

bool tlsclientRaceIsMainLine(const tlsclient_lstate_t *ls)
{
    return ls->role == kTlsClientLineRoleRaceMain;
}

bool tlsclientRaceIsChildLine(const tlsclient_lstate_t *ls)
{
    return ls->role == kTlsClientLineRoleRaceChild;
}

void tlsclientLinestateInitializeRaceMain(tlsclient_lstate_t *ls, uint32_t child_count)
{
    *ls = (tlsclient_lstate_t) {
        .role                    = kTlsClientLineRoleRaceMain,
        .race_child_count        = child_count,
        .race_open_children      = 0,
        .race_child_lines        = memoryAllocateZero(sizeof(line_t *) * (size_t) child_count),
        .race_selected_child     = NULL,
        .race_main_line          = NULL,
        .race_main_est_forwarded = false,
        .race_pending_up         = bufferqueueCreate(kTlsClientRacePendingQueueCap),
    };
}

void tlsclientLinestateInitializeRaceChild(tlsclient_lstate_t *ls, line_t *main_l, uint32_t slot,
                                           uint32_t sni_index, const char *selected_sni)
{
    lineLock(main_l);

    *ls = (tlsclient_lstate_t) {
        .role               = kTlsClientLineRoleRaceChild,
        .selected_sni_index = sni_index,
        .selected_sni       = selected_sni,
        .race_child_slot    = slot,
        .race_main_line     = main_l,
    };
}

void tlsclientLinestateDestroyRaceMain(tlsclient_lstate_t *ls)
{
    if (ls->role != kTlsClientLineRoleRaceMain)
    {
        return;
    }

    bufferqueueDestroy(&ls->race_pending_up);
    memoryFree(ls->race_child_lines);
    memoryZeroAligned32(ls, sizeof(*ls));
}

void tlsclientLinestateDestroyRaceChild(tlsclient_lstate_t *ls)
{
    if (ls->role != kTlsClientLineRoleRaceChild)
    {
        return;
    }

    memoryZeroAligned32(ls, sizeof(*ls));
}

static bool tlsclientRaceMainLineStillOpen(tunnel_t *t, line_t *main_l)
{
    if (! lineIsAlive(main_l))
    {
        return false;
    }

    tlsclient_lstate_t *main_ls = lineGetState(main_l, t);
    return main_ls->role == kTlsClientLineRoleRaceMain;
}

static bool tlsclientRaceFlushPendingToSelected(tunnel_t *t, line_t *main_l, line_t *child_l)
{
    tlsclient_lstate_t *main_ls = lineGetState(main_l, t);

    while (bufferqueueGetBufCount(&main_ls->race_pending_up) > 0)
    {
        sbuf_t *buf = bufferqueuePopFront(&main_ls->race_pending_up);
        if (! withLineLockedWithBuf(child_l, tlsclientTunnelUpStreamPayload, t, buf))
        {
            return false;
        }

        if (! lineIsAlive(main_l))
        {
            return false;
        }
    }

    return true;
}

static void tlsclientRaceCloseMainLineInternal(tunnel_t *t, line_t *main_l, bool send_downstream_finish)
{
    if (! lineIsAlive(main_l))
    {
        return;
    }

    lineLock(main_l);

    tlsclient_lstate_t *main_ls = lineGetState(main_l, t);
    if (main_ls->role != kTlsClientLineRoleRaceMain)
    {
        lineUnlock(main_l);
        return;
    }

    line_t  **children   = main_ls->race_child_lines;
    uint32_t child_count = main_ls->race_child_count;

    main_ls->race_child_lines    = NULL;
    main_ls->race_child_count    = 0;
    main_ls->race_open_children  = 0;
    main_ls->race_selected_child = NULL;

    tlsclientLinestateDestroyRaceMain(main_ls);

    if (children != NULL)
    {
        for (uint32_t i = 0; i < child_count; ++i)
        {
            if (children[i] != NULL && lineIsAlive(children[i]))
            {
                tlsclientRaceCloseChildLine(t, children[i], false);
            }
        }

        memoryFree(children);
    }

    if (send_downstream_finish && lineIsAlive(main_l))
    {
        tunnelPrevDownStreamFinish(t, main_l);
    }

    lineUnlock(main_l);
}

void tlsclientRaceCloseMainLine(tunnel_t *t, line_t *main_l)
{
    tlsclientRaceCloseMainLineInternal(t, main_l, true);
}

void tlsclientRaceCloseMainLineFromUpstream(tunnel_t *t, line_t *main_l)
{
    tlsclientRaceCloseMainLineInternal(t, main_l, false);
}

static void tlsclientRaceCloseChildLineInternal(tunnel_t *t, line_t *child_l, bool force_close_main,
                                                bool send_upstream_finish)
{
    if (! lineIsAlive(child_l))
    {
        return;
    }

    lineLock(child_l);

    tlsclient_lstate_t *child_ls = lineGetState(child_l, t);
    if (child_ls->role != kTlsClientLineRoleRaceChild)
    {
        lineUnlock(child_l);
        return;
    }

    line_t  *main_l            = child_ls->race_main_line;
    uint32_t child_slot        = child_ls->race_child_slot;
    bool     should_close_main = force_close_main;

    if (main_l != NULL)
    {
        tlsclient_lstate_t *main_ls = lineGetState(main_l, t);

        if (main_ls->role == kTlsClientLineRoleRaceMain)
        {
            if (child_slot < main_ls->race_child_count && main_ls->race_child_lines[child_slot] == child_l)
            {
                main_ls->race_child_lines[child_slot] = NULL;
                if (main_ls->race_open_children > 0)
                {
                    main_ls->race_open_children -= 1;
                }
            }

            if (main_ls->race_selected_child == child_l)
            {
                main_ls->race_selected_child = NULL;
                should_close_main            = true;
            }
            else if (! should_close_main && main_ls->race_selected_child == NULL &&
                     main_ls->race_open_children == 0)
            {
                should_close_main = true;
            }
        }
    }

    tlsclientReleaseActiveSniLine(t, child_ls);
    tlsclientLinestateDestroy(child_ls);

    if (send_upstream_finish)
    {
        tunnelNextUpStreamFinish(t, child_l);
    }
    if (lineIsAlive(child_l))
    {
        lineDestroy(child_l);
    }
    lineUnlock(child_l);

    if (should_close_main && main_l != NULL && lineIsAlive(main_l))
    {
        tlsclientRaceCloseMainLine(t, main_l);
    }

    if (main_l != NULL)
    {
        lineUnlock(main_l);
    }
}

void tlsclientRaceCloseChildLine(tunnel_t *t, line_t *child_l, bool force_close_main)
{
    tlsclientRaceCloseChildLineInternal(t, child_l, force_close_main, true);
}

void tlsclientRaceCloseChildLineFromDownstream(tunnel_t *t, line_t *child_l, bool force_close_main)
{
    tlsclientRaceCloseChildLineInternal(t, child_l, force_close_main, false);
}

static bool tlsclientRaceSelectChild(tunnel_t *t, line_t *child_l)
{
    tlsclient_lstate_t *child_ls = lineGetState(child_l, t);
    line_t             *main_l   = child_ls->race_main_line;

    if (main_l == NULL || ! lineIsAlive(main_l))
    {
        tlsclientRaceCloseChildLine(t, child_l, false);
        return false;
    }

    tlsclient_lstate_t *main_ls = lineGetState(main_l, t);
    if (main_ls->role != kTlsClientLineRoleRaceMain)
    {
        tlsclientRaceCloseChildLine(t, child_l, false);
        return false;
    }

    if (main_ls->race_selected_child != NULL && main_ls->race_selected_child != child_l)
    {
        tlsclientRaceCloseChildLine(t, child_l, false);
        return false;
    }

    line_t  **losers     = NULL;
    uint32_t loser_count = 0;

    if (main_ls->race_selected_child == NULL)
    {
        if (main_ls->race_child_count > 1)
        {
            losers = memoryAllocate(sizeof(line_t *) * (size_t) (main_ls->race_child_count - 1));
        }

        main_ls->race_selected_child = child_l;

        for (uint32_t i = 0; i < main_ls->race_child_count; ++i)
        {
            line_t *candidate = main_ls->race_child_lines[i];
            if (candidate == NULL || candidate == child_l)
            {
                continue;
            }

            losers[loser_count++]       = candidate;
            main_ls->race_child_lines[i] = NULL;
        }

        main_ls->race_open_children = 1;

        if (! main_ls->race_main_est_forwarded)
        {
            main_ls->race_main_est_forwarded = true;

            if (! lineIsEstablished(main_l))
            {
                lineMarkEstablished(main_l);
            }

            if (! withLineLocked(main_l, tunnelPrevDownStreamEst, t))
            {
                for (uint32_t i = 0; i < loser_count; ++i)
                {
                    if (lineIsAlive(losers[i]))
                    {
                        tlsclientRaceCloseChildLine(t, losers[i], false);
                    }
                }

                memoryFree(losers);
                if (lineIsAlive(child_l))
                {
                    tlsclientRaceCloseChildLine(t, child_l, false);
                }
                return false;
            }
        }
    }

    for (uint32_t i = 0; i < loser_count; ++i)
    {
        if (lineIsAlive(losers[i]))
        {
            tlsclientRaceCloseChildLine(t, losers[i], false);
            if (! lineIsAlive(main_l))
            {
                memoryFree(losers);
                return false;
            }
        }
    }

    memoryFree(losers);

    if (! tlsclientRaceFlushPendingToSelected(t, main_l, child_l))
    {
        if (lineIsAlive(main_l))
        {
            tlsclientRaceCloseMainLine(t, main_l);
        }
        return false;
    }

    return lineIsAlive(main_l);
}

void tlsclientRaceOnChildHandshakeComplete(tunnel_t *t, line_t *child_l)
{
    tlsclient_lstate_t *child_ls = lineGetState(child_l, t);

    if (child_ls->role != kTlsClientLineRoleRaceChild || ! child_ls->handshake_completed)
    {
        return;
    }

    discard tlsclientRaceSelectChild(t, child_l);
}

void tlsclientRaceTimeoutTask(tunnel_t *t, line_t *main_l)
{
    tlsclient_tstate_t *ts      = tunnelGetState(t);
    tlsclient_lstate_t *main_ls = lineGetState(main_l, t);

    if (main_ls->role != kTlsClientLineRoleRaceMain || main_ls->race_selected_child != NULL)
    {
        return;
    }

    LOGW("TlsClient: SNI race timed out waiting for a successful TLS handshake after %u ms",
         (unsigned int) ts->race_timeout_ms);
    tlsclientRaceCloseMainLine(t, main_l);
}

void tlsclientRaceUpStreamInit(tunnel_t *t, line_t *main_l)
{
    tlsclient_tstate_t *ts      = tunnelGetState(t);
    tlsclient_lstate_t *main_ls = lineGetState(main_l, t);

    uint32_t *indices = memoryAllocate(sizeof(uint32_t) * (size_t) ts->race_tries);
    uint32_t child_count = tlsclientSelectRaceSniIndices(ts, indices, ts->race_tries);

    tlsclientLinestateInitializeRaceMain(main_ls, child_count);
    lineLock(main_l);

    for (uint32_t i = 0; i < child_count; ++i)
    {
        line_t             *child_l  = lineCreate(tunnelchainGetLinePools(tunnelGetChain(t)), lineGetWID(main_l));
        tlsclient_lstate_t *child_ls = lineGetState(child_l, t);
        uint32_t            sni_index = indices[i];

        tlsclientLinestateInitializeRaceChild(child_ls, main_l, i, sni_index, ts->snis[sni_index]);

        main_ls = lineGetState(main_l, t);
        main_ls->race_child_lines[i] = child_l;
        main_ls->race_open_children += 1;

        tlsclientPerformUpStreamInit(t, child_l);

        if (! tlsclientRaceMainLineStillOpen(t, main_l))
        {
            memoryFree(indices);
            lineUnlock(main_l);
            return;
        }
    }

    memoryFree(indices);

    main_ls = lineGetState(main_l, t);
    if (main_ls->race_open_children == 0)
    {
        tlsclientRaceCloseMainLine(t, main_l);
        lineUnlock(main_l);
        return;
    }

    lineScheduleDelayedTask(main_l, tlsclientRaceTimeoutTask, ts->race_timeout_ms, t);
    lineUnlock(main_l);
}
