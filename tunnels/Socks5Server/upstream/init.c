#include "structure.h"

#include "loggers/network_logger.h"

void socks5serverTunnelUpStreamInit(tunnel_t *t, line_t *l)
{
    socks5serverRequireCurrentLineWorker(l, "upstream Init");

    if (lineGetSourceAddressContext(l)->proto_tcp)
    {
        socks5serverLinestateInitialize(lineGetState(l, t), t, l, kSocks5ServerLineKindControlTcp);
        return;
    }

    if (lineGetSourceAddressContext(l)->proto_udp)
    {
        tunnel_chain_t *chain = tunnelGetChain(t);
        if (tunnelchainIsWorkerPacketLine(chain, l))
        {
            socks5serverLinestateInitialize(lineGetState(l, t), t, l, kSocks5ServerLineKindNone);
            return;
        }

        socks5server_tstate_t          *ts         = tunnelGetState(t);
        udplistener_dynamic_line_info_t info       = {0};
        const wid_t                     wid        = lineGetWID(l);
        const uint16_t                  local_port = lineGetRoutingContext(l)->local_listener_port;
        bool valid = ts->dynamic_provider.instance != NULL && ts->dynamic_provider.get_line_info != NULL;
        if (valid)
        {
            valid = ts->dynamic_provider.get_line_info(ts->dynamic_provider.instance, l, &info);
        }

        valid = valid && info.is_dynamic && udplistenerDynamicEndpointHandleIsValid(info.handle) &&
                info.expected_wid == wid && info.handle.owner_wid == wid && info.generation == info.handle.generation &&
                info.bound_local_port != 0 && info.bound_local_port == local_port &&
                socks5serverAssociationIsActive(t, wid, info.handle, info.bound_local_port, NULL);
        if (! valid)
        {
            socks5serverLinestateInitialize(lineGetState(l, t), t, l, kSocks5ServerLineKindRejected);
            LOGW("Socks5Server: rejected UDP ingress without an active local dynamic endpoint association on worker %u",
                 (unsigned int) wid);
            return;
        }

        socks5server_assoc_entry_t *assoc = socks5serverFindWorkerAssociation(t, wid, info.generation);
        assert(assoc != NULL);

        socks5server_lstate_t *ls = lineGetState(l, t);
        socks5serverLinestateInitialize(ls, t, l, kSocks5ServerLineKindUdpClient);
        ls->dynamic_handle = info.handle;
        ls->user_handle    = assoc->user_handle;
        if (assoc->auth_username != NULL)
        {
            ls->auth_username = stringDuplicate(assoc->auth_username);
        }
        if (assoc->auth_password != NULL)
        {
            ls->auth_password = stringDuplicate(assoc->auth_password);
        }

        if ((assoc->auth_username != NULL && ls->auth_username == NULL) ||
            (assoc->auth_password != NULL && ls->auth_password == NULL))
        {
            socks5serverLinestateDestroy(ls);
            socks5serverLinestateInitialize(lineGetState(l, t), t, l, kSocks5ServerLineKindRejected);
            LOGW("Socks5Server: rejected UDP ingress because authenticated association metadata could not be copied");
            return;
        }

        socks5serverRecordLineUser(l, ls, &ls->user_handle);
        return;
    }

    socks5serverLinestateInitialize(lineGetState(l, t), t, l, kSocks5ServerLineKindNone);
    tunnelNextUpStreamInit(t, l);
}
