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
// cOFOrq/KdE/fVZRZFY307An+F8PAxYbrBRAErgK6CFo=
// ldnNQe9VwBtL5jJbJzNyWCKfRbj8/50sGtqJsh3ErGA=

// YIJmMTi+hQ4o/FBx1vWxLQRrOV4ShetmmjcHRveClBg=
// uJb7QdPW9u5+1SjXUNf0VYeZzyFwT2iJCJ7hlH7f71k=

static void wireguarddeviceInit(wireguard_device_t *device, wireguard_device_init_data_t *data)
{
    assert(data != NULL);

    uint8_t private_key[WIREGUARD_PRIVATE_KEY_LEN];
    size_t  private_key_len = sizeof(private_key);

    // We need to initialise the wireguard module
    wireguardInit();

    if (BASE64_ENCODE_OUT_SIZE(private_key_len) != stringLength((char *) data->private_key))
    {
        LOGE("Error: WireGuardDevice->settings->privatekey (string field) : The data was empty or invalid");
        terminateProgram(1);
    }

    if (wwBase64Decode((char *) data->private_key, (unsigned int) stringLength((char *) data->private_key),
                       private_key) == WIREGUARD_PRIVATE_KEY_LEN)
    {

        // Per-wireguard ts/device setup
        if (wireguardDeviceInit(device, private_key))
        {
            // We set up no state flags here - caller should set them
            // NETIF_FLAG_LINK_UP is automatically set/cleared when at least one peer is connected
            device->status_connected = 0;
        }
        else
        {
            memoryFree(device);
            terminateProgram(1);
        }
    }
    else
    {
        memoryFree(device);
        terminateProgram(1);
    }
}

tunnel_t *wireguarddeviceTunnelCreate(node_t *node)
{
    tunnel_t *t = packettunnelCreate(node, sizeof(wgd_tstate_t), sizeof(wgd_lstate_t));

    t->fnPayloadU = &wireguarddeviceTunnelUpStreamPayload;
    t->fnPayloadD = &wireguarddeviceTunnelDownStreamPayload;
    t->onPrepair = &wireguarddeviceTunnelOnPrepair;
    t->onStart   = &wireguarddeviceTunnelOnStart;

    wgd_tstate_t *state = tunnelGetState(t);

    state->tunnel = t;
    mutexInit(&state->mutex);

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

    wireguard_device_init_data_t device_configuration = {0};
    device_configuration.private_key                  = (const uint8_t *) device_private_key;
    state->device_configuration                       = device_configuration;

    wireguard_device_t *device = &state->wg_device;
    wireguarddeviceInit(device, &state->device_configuration);

    if (! device)
    {
        LOGF("Error: wireguarddeviceInit failed");
        return NULL;
    }

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

        wireguard_peer_init_data_t peer = {0};
        wireguardifPeerInit(&peer);
        peer.public_key    = (const uint8_t *) peer_public_key;
        peer.preshared_key = (const uint8_t *) peer_preshared_key;
        { //  10.0.0.1/24, fd86:ea04:1115::1/64
            char *peer_allowed_ips_nospace = stringNewWithoutSpace(peer_allowed_ips);
            memoryFree(peer_allowed_ips);

            char *coma_ptr = stringChr(peer_allowed_ips_nospace, ',');

            if (! coma_ptr)
            {
                LOGF("Error: peer_allowed_ips_nospace does not contain a ','");
                return NULL;
            }
            coma_ptr[0]     = '\0';
            char *ipv4_part = peer_allowed_ips_nospace;
            char *ipv6_part = coma_ptr + 1;

            if (! verifyIPCdir(ipv4_part))
            {
                LOGF("JSON Error: WireGuardDevice->settings->peers [ index %d  ]->allowedips (string field) (ipv4 "
                     "part) : The data "
                     "was empty or invalid",
                     i);
                return NULL;
            }
            if (! verifyIPCdir(ipv6_part))
            {
                LOGF("JSON Error: WireGuardDevice->settings->peers [ index %d  ]->allowedips (string field) (ipv6 "
                     "part): The data "
                     "was empty or invalid",
                     i);
                return NULL;
            }
            /*
                TODO
                currently only supports ipv4
            */
            parseIPWithSubnetMask(ipv4_part,  &peer.allowed_ip,
                                  &peer.allowed_mask);
        }
        {
            char *colon_ptr = stringChr(peer_endpoint, ':');
            if (! colon_ptr)
            {
                LOGF("Error: peer_endpoint does not contain a ':'");
                return NULL;
            }
            colon_ptr[0]                = '\0';
            char    *peer_endpoint_ip   = peer_endpoint;
            char    *peer_endpoint_port = colon_ptr + 1;
            uint16_t port               = (uint16_t) atoi(peer_endpoint_port);
            if (port == 0)
            {
                LOGF("Error: peer_endpoint_port is not a valid port number");
                return NULL;
            }
            sockaddr_u temp;
            resolveAddr(peer_endpoint_ip, &temp);
            ip4_addr_t ipaddr;
            ip4_addr_set_u32(&ipaddr, temp.sin.sin_addr.s_addr);

            ip_addr_copy_from_ip4(peer.endpoint_ip, ipaddr);
            peer.endpoint_port = port;
        }
        // Add the peer
        if (wireguardifAddPeer(device, &peer, NULL) != ERR_OK)
        {
            LOGF("Error: wireguardifAddPeer failed");
            return NULL;
        }
    }

    return t;
}
