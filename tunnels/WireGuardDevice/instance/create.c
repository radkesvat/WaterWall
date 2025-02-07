#include "structure.h"

#include "loggers/network_logger.h"

/*

    [Interface]
    PrivateKey = zZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZ=  # Replace with your actual private key
    Address = 10.0.0.1/24, fd86:ea04:1115::1/64            # IPv4 and IPv6 addresses for this interface
    ListenPort = 51820                                     # Port on which the server listens
    FwMark = 0x42                                         # Optional: Firewall mark for routing
    MTU = 1420                                            # Optional: Maximum Transmission Unit
    Table = off                                           # Optional: Routing table (auto, main, off)
    SaveConfig = true                                     # Save peer configs automatically when wg-quick quits
    PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
    PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE
    PreUp = echo "Starting WireGuard interface..."        # Optional: Command to run before bringing up the interface
    PreDown = echo "Stopping WireGuard interface..."      # Optional: Command to run before taking down the interface

    [Peer]
    PublicKey = yYyYyYyYyYyYyYyYyYyYyYyYyYyYyYyYyYyYyYyY=  # Replace with the public key of the peer
    PresharedKey = xXxXxXxXxXxXxXxXxXxXxXxXxXxXxXxXxXxXxX= # Optional: Pre-shared key for additional security
    AllowedIPs = 10.0.0.2/32, fd86:ea04:1115::2/128       # IP ranges that are allowed to reach this peer
    Endpoint = peer.example.com:51820                     # Public endpoint of the peer (hostname or IP and port)
    PersistentKeepalive = 25                              # Interval in seconds for keepalive messages (useful for NAT)

    [Peer]
    PublicKey = wWwWwWwWwWwWwWwWwWwWwWwWwWwWwWwWwWwWwWwW=  # Another peer's public key
    PresharedKey = vVvVvVvVvVvVvVvVvVvVvVvVvVvVvVvVvVvVvV= # Another pre-shared key
    AllowedIPs = 10.0.0.3/32, fd86:ea04:1115::3/128       # IP ranges for this peer
    Endpoint = another-peer.example.com:51821             # Endpoint for this peer
    PersistentKeepalive = 15                              # Keepalive interval for this peer
*/

tunnel_t *wireguarddeviceTunnelCreate(node_t *node)
{
    tunnel_t *t = tunnelCreate(node, sizeof(wgd_tstate_t), sizeof(wgd_lstate_t));

    t->fnInitU    = &wireguarddeviceTunnelUpStreamInit;
    t->fnEstU     = &wireguarddeviceTunnelUpStreamEst;
    t->fnFinU     = &wireguarddeviceTunnelUpStreamFinish;
    t->fnPayloadU = &wireguarddeviceTunnelUpStreamPayload;
    t->fnPauseU   = &wireguarddeviceTunnelUpStreamPause;
    t->fnResumeU  = &wireguarddeviceTunnelUpStreamResume;

    t->fnInitD    = &wireguarddeviceTunnelDownStreamInit;
    t->fnEstD     = &wireguarddeviceTunnelDownStreamEst;
    t->fnFinD     = &wireguarddeviceTunnelDownStreamFinish;
    t->fnPayloadD = &wireguarddeviceTunnelDownStreamPayload;
    t->fnPauseD   = &wireguarddeviceTunnelDownStreamPause;
    t->fnResumeD  = &wireguarddeviceTunnelDownStreamResume;

    wgd_tstate_t *state = tunnelGetState(t);


    char *device_private_key = NULL;

    const cJSON *settings = node->node_settings_json;

    if (! checkJsonIsObjectAndHasChild(settings))
    {
        LOGF("JSON Error: WireGuardDevice->settings (object field) : The object was empty or invalid");
        return NULL;
    }

    if (! getStringFromJsonObject(&device_private_key, node->node_settings_json, "privatekey"))
    {
        LOGF("JSON Error: WireGuardDevice->settings->privatekey (string field) : The data was empty or invalid");
        return NULL;
    }

    wgdevice_init_data_t device_configuration = {0};
    device_configuration.private_key = device_private_key;

    state->device_configuration = device_configuration;
    wireguardifInit(state);



    const cJSON *peers_jarray = cJSON_GetObjectItemCaseSensitive(settings, "peers");
    if (! cJSON_IsArray(peers_jarray))
    {
        LOGF("JSON Error: WireGuardDevice->settings->peers (array field) : The data was empty or invalid");
        return NULL;
    }

    int peers_count = cJSON_GetArraySize(peers_jarray);
    if (peers_count <= 0)
    {
        LOGF("JSON Error: WireGuardDevice->settings->peers (array field) :  peers_count <= 0");
        return NULL;
    }
    if (peers_count > WIREGUARD_MAX_PEERS)
    {
        LOGF("JSON Error: WireGuardDevice->settings->peers (array field) : peers_count > WIREGUARD_MAX_PEERS");
        return NULL;
    }

    for (int i = 0; i < peers_count; i++)
    {
        cJSON *peer_jobject = cJSON_GetArrayItem(peers_jarray, i);
        if (! checkJsonIsObjectAndHasChild(peer_jobject))
        {
            LOGF("JSON Error: WireGuardDevice->settings->peers (array of objects field) index %d : The data was empty "
                 "or invalid",
                 i);
            return NULL;
        }

        char *peer_public_key     = NULL;
        char *peer_preshared_key  = NULL;
        char *peer_allowed_ips    = NULL;
        char *peer_endpoint       = NULL;
        int   persistentkeepalive = 0;

        if (! getStringFromJsonObject(&peer_public_key, peer_jobject, "publickey"))
        {
            LOGF("JSON Error: WireGuardDevice->settings->peers [ index %d  ]->publickey (string field) : The data was "
                 "empty or invalid",
                 i);
            return NULL;
        }
        getStringFromJsonObject(&peer_preshared_key, peer_jobject, "presharedkey");

        if (! getStringFromJsonObject(&peer_allowed_ips, peer_jobject, "allowedips"))
        {
            LOGF("JSON Error: WireGuardDevice->settings->peers [ index %d  ]->allowedips (string field) : The data was "
                 "empty or invalid",
                 i);
            return NULL;
        }
        if (! getStringFromJsonObject(&peer_endpoint, peer_jobject, "endpoint"))
        {
            LOGF("JSON Error: WireGuardDevice->settings->peers [ index %d  ]->endpoint (string field) : The data was "
                 "empty or invalid",
                 i);
            return NULL;
        }
        getIntFromJsonObject(&persistentkeepalive, peer_jobject, "persistentkeepalive");


        // Create the peer

    }

    return t;
}
