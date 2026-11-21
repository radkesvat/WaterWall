#include "structure.h"

void halfduplexclientTunnelUpStreamInit(tunnel_t *t, line_t *main)
{
    address_context_t *destination = lineGetDestinationAddressContext(main);
    if (addresscontextSelectTransport(destination, kAddressContextTransportTcp) == 0)
    {
        tunnelLogTransportRefusal(t, destination, kAddressContextTransportTcp);
        tunnelPrevDownStreamFinish(t, main);
        return;
    }
    addresscontextSetOnlyProtocol(destination, IP_PROTO_TCP);

    halfduplexclient_tstate_t *ts = tunnelGetState(t);
    halfduplexclient_pair_t   *pair = halfduplexclientCreatePair(t, main);
    pair->starting                  = true;
    ++pair->refs;
    lineRef(main);
    generic_pool_t **pools = tunnelchainGetLinePools(tunnelGetChain(t));
    wid_t            wid   = lineGetWID(main);
    pair->upload           = lineCreate(pools, wid);
    addresscontextSetOnlyProtocol(lineGetDestinationAddressContext(pair->upload), IP_PROTO_TCP);
    halfduplexclientSetPair(t, pair->upload, pair);
    if (lineCallWithRef(pair->upload, tunnelUpStreamInit, ts->upload_tunnel) && lineIsAlive(main) && pair->main != NULL)
    {
        pair->download = lineCreate(pools, wid);
        addresscontextSetOnlyProtocol(lineGetDestinationAddressContext(pair->download), IP_PROTO_TCP);
        halfduplexclientSetPair(t, pair->download, pair);
        if (lineCallWithRef(pair->download, tunnelUpStreamInit, ts->download_tunnel) && lineIsAlive(main) &&
            pair->main != NULL)
        {
            pair->starting = false;
            if (pair->pending_read_pause)
            {
                // Apply the remembered read hold before Est releases any queued application input.
                pair->pumping = true;
                halfduplexclientSetPrevPaused(t, main, true);
                pair->pumping = false;
            }
            if (lineIsAlive(main) && pair->main != NULL)
                halfduplexclientNotifyEstablished(pair);
            halfduplexclientPump(pair, NULL);
        }
    }
    lineUnref(main);
    halfduplexclientReleasePair(pair);
}
