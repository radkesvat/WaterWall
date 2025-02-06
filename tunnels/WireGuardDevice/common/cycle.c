#include "structure.h"

void wireguarddeviceCycle(void *arg)
{
    wireguard_device_t *device = (wireguard_device_t *) arg;
    wireguard_peer_t   *peer;
    int                      x;
    // Reschedule this timer
    sys_timeout(WIREGUARDIF_TIMER_MSECS, wireguardif_tmr, device);

    // Check periodic things
    bool link_up = false;
    for (x = 0; x < WIREGUARD_MAX_PEERS; x++)
    {
        peer = &device->peers[x];
        if (peer->valid)
        {
            // Do we need to rekey / send a handshake?
            if (should_reset_peer(peer))
            {
                // Nothing back for too long - we should wipe out all crypto state
                keypair_destroy(&peer->next_keypair);
                keypair_destroy(&peer->curr_keypair);
                keypair_destroy(&peer->prev_keypair);
                // TODO: Also destroy handshake?

                // Revert back to default IP/port if these were altered
                peer->ip   = peer->connect_ip;
                peer->port = peer->connect_port;
            }
            if (should_destroy_current_keypair(peer))
            {
                // Destroy current keypair
                keypair_destroy(&peer->curr_keypair);
            }
            if (should_send_keepalive(peer))
            {
                wireguardif_send_keepalive(device, peer);
            }
            if (should_send_initiation(peer))
            {
                wireguard_start_handshake(device->netif, peer);
            }

            if ((peer->curr_keypair.valid) || (peer->prev_keypair.valid))
            {
                link_up = true;
            }
        }
    }

    if (! link_up)
    {
        // Clear the IF-UP flag on netif
        netif_set_link_down(device->netif);
    }
}
