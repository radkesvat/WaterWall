#include "structure.h"

#include "loggers/network_logger.h"

void connectionfisherclientTunnelUpStreamInit(tunnel_t *t, line_t *main_l)
{
    connectionfisherclient_tstate_t *ts      = tunnelGetState(t);
    connectionfisherclient_lstate_t *main_ls = lineGetState(main_l, t);

    connectionfisherclientLinestateInitializeMain(main_ls, main_l, ts->simultaneous_tries_perline);

    for (uint32_t i = 0; i < ts->simultaneous_tries_perline; ++i)
    {
        line_t *child_l = lineCreate(tunnelchainGetLinePools(tunnelGetChain(t)), lineGetWID(main_l));
        connectionfisherclient_lstate_t *child_ls = lineGetState(child_l, t);

        connectionfisherclientLinestateInitializeChild(child_ls, child_l, main_l, i);
        main_ls->child_lines[i] = child_l;
        main_ls->open_child_count += 1;

        if (! withLineLocked(child_l, tunnelNextUpStreamInit, t))
        {
            connectionfisherclient_lstate_t *check_main_ls = lineGetState(main_l, t);
            if (! lineIsAlive(main_l) || check_main_ls->role != kConnectionFisherClientRoleMain)
            {
                return;
            }

            continue;
        }

        if (! connectionfisherclientSendPing(t, child_l))
        {
            connectionfisherclient_lstate_t *check_main_ls = lineGetState(main_l, t);
            if (! lineIsAlive(main_l) || check_main_ls->role != kConnectionFisherClientRoleMain)
            {
                return;
            }
        }

        {
            connectionfisherclient_lstate_t *check_main_ls = lineGetState(main_l, t);
            if (! lineIsAlive(main_l) || check_main_ls->role != kConnectionFisherClientRoleMain)
            {
                return;
            }
        }
    }

    if (main_ls->open_child_count == 0)
    {
        connectionfisherclientCloseMainLine(t, main_l);
        return;
    }

    lineScheduleDelayedTask(main_l, connectionfisherclientTimeoutTask, kConnectionFisherTimeoutMs, t);
}
