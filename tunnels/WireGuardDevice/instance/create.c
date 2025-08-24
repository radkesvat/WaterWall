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

static bool validatePrivateKeyLength(const char *private_key)
{
    uint8_t dummy_key[WIREGUARD_PRIVATE_KEY_LEN];
    size_t private_key_len = sizeof(dummy_key);
    
    if (BASE64_ENCODE_OUT_SIZE(private_key_len) != stringLength((char *) private_key))
    {
        LOGE("Error: WireGuardDevice->settings->privatekey (string field) : The data was empty or invalid");
        return false;
    }
    return true;
}

static bool decodeAndInitializeDevice(wireguard_device_t *device, const char *private_key)
{
    uint8_t decoded_key[WIREGUARD_PRIVATE_KEY_LEN];
    
    if (wwBase64Decode((char *) private_key, (unsigned int) stringLength((char *) private_key),
                       decoded_key) != WIREGUARD_PRIVATE_KEY_LEN)
    {
        return false;
    }

    if (!wireguardDeviceInit(device, decoded_key))
    {
        return false;
    }

    device->status_connected = 0;
    return true;
}

static tunnel_t *createBaseTunnel(node_t *node)
{
    tunnel_t *t = packettunnelCreate(node, sizeof(wgd_tstate_t), 0);

    t->fnPayloadU = &wireguarddeviceTunnelUpStreamPayload;
    t->fnPayloadD = &wireguarddeviceTunnelDownStreamPayload;
    t->onPrepare = &wireguarddeviceTunnelOnPrepair;
    t->onStart   = &wireguarddeviceTunnelOnStart;

    wgd_tstate_t *state = tunnelGetState(t);
    state->tunnel = t;
    mutexInit(&state->mutex);
    
    return t;
}

static bool parseAllowedIps(const char *allowed_ips, wireguard_peer_init_data_t *peer, int peer_index)
{
    char *allowed_ips_nospace = stringNewWithoutSpace(allowed_ips);
    char *comma_ptr = stringChr(allowed_ips_nospace, ',');

    if (!comma_ptr)
    {
        LOGF("Error: peer_allowed_ips_nospace does not contain a ','");
        memoryFree(allowed_ips_nospace);
        return false;
    }

    comma_ptr[0] = '\0';
    char *ipv4_part = allowed_ips_nospace;
    char *ipv6_part = comma_ptr + 1;

    if (!verifyIPCdir(ipv4_part))
    {
        LOGF("JSON Error: WireGuardDevice->settings->peers [ index %d  ]->allowedips (string field) (ipv4 part) : The data was empty or invalid", peer_index);
        memoryFree(allowed_ips_nospace);
        return false;
    }

    if (!verifyIPCdir(ipv6_part))
    {
        LOGF("JSON Error: WireGuardDevice->settings->peers [ index %d  ]->allowedips (string field) (ipv6 part): The data was empty or invalid", peer_index);
        memoryFree(allowed_ips_nospace);
        return false;
    }

    /* TODO: currently only supports ipv4 */
    parseIPWithSubnetMask(ipv4_part, &peer->allowed_ip, &peer->allowed_mask);
    memoryFree(allowed_ips_nospace);
    return true;
}

static bool parseEndpoint(const char *endpoint, wireguard_peer_init_data_t *peer)
{
    char *endpoint_copy = stringDuplicate(endpoint);
    char *colon_ptr = stringChr(endpoint_copy, ':');
    
    if (!colon_ptr)
    {
        LOGF("Error: peer_endpoint does not contain a ':'");
        memoryFree(endpoint_copy);
        return false;
    }

    colon_ptr[0] = '\0';
    char *endpoint_ip = endpoint_copy;
    char *endpoint_port = colon_ptr + 1;
    uint16_t port = (uint16_t) atoi(endpoint_port);
    
    if (port == 0)
    {
        LOGF("Error: peer_endpoint_port is not a valid port number");
        memoryFree(endpoint_copy);
        return false;
    }

    sockaddr_u temp;
    resolveAddr(endpoint_ip, &temp);
    ip4_addr_t ipaddr;
    ip4_addr_set_u32(&ipaddr, temp.sin.sin_addr.s_addr);

    ip_addr_copy_from_ip4(peer->endpoint_ip, ipaddr);
    peer->endpoint_port = port;
    
    memoryFree(endpoint_copy);
    return true;
}

static bool extractPeerFields(cJSON *peer_object, char **public_key, char **preshared_key, 
                             char **allowed_ips, char **endpoint, int *keepalive, int peer_index)
{
    if (!getStringFromJsonObject(public_key, peer_object, "publickey"))
    {
        LOGF("JSON Error: WireGuardDevice->settings->peers [ index %d  ]->publickey (string field) : The data was empty or invalid", peer_index);
        return false;
    }

    getStringFromJsonObject(preshared_key, peer_object, "presharedkey");

    if (!getStringFromJsonObject(allowed_ips, peer_object, "allowedips"))
    {
        LOGF("JSON Error: WireGuardDevice->settings->peers [ index %d  ]->allowedips (string field) : The data was empty or invalid", peer_index);
        return false;
    }

    if (!getStringFromJsonObject(endpoint, peer_object, "endpoint"))
    {
        LOGF("JSON Error: WireGuardDevice->settings->peers [ index %d  ]->endpoint (string field) : The data was empty or invalid", peer_index);
        return false;
    }

    getIntFromJsonObject(keepalive, peer_object, "persistentkeepalive");
    return true;
}

static bool processPeer(cJSON *peer_object, wireguard_device_t *device, int peer_index)
{
    char *peer_public_key = NULL;
    char *peer_preshared_key = NULL;
    char *peer_allowed_ips = NULL;
    char *peer_endpoint = NULL;
    int persistentkeepalive = 0;

    if (!extractPeerFields(peer_object, &peer_public_key, &peer_preshared_key, 
                          &peer_allowed_ips, &peer_endpoint, &persistentkeepalive, peer_index))
    {
        return false;
    }

    wireguard_peer_init_data_t peer = {0};
    wireguardifPeerInit(&peer);
    peer.public_key = (const uint8_t *) peer_public_key;
    peer.preshared_key = (const uint8_t *) peer_preshared_key;

    if (!parseAllowedIps(peer_allowed_ips, &peer, peer_index))
    {
        memoryFree(peer_allowed_ips);
        return false;
    }
    memoryFree(peer_allowed_ips);

    if (!parseEndpoint(peer_endpoint, &peer))
    {
        return false;
    }

    if (wireguardifAddPeer(device, &peer, NULL) != ERR_OK)
    {
        LOGF("Error: wireguardifAddPeer failed");
        return false;
    }

    return true;
}

static bool validatePeersArray(const cJSON *peers_array)
{
    if (!cJSON_IsArray(peers_array))
    {
        LOGF("JSON Error: WireGuardDevice->settings->peers (array field) : The data was empty or invalid");
        return false;
    }

    int peers_count = cJSON_GetArraySize(peers_array);
    if (peers_count <= 0)
    {
        LOGF("JSON Error: WireGuardDevice->settings->peers (array field) :  peers_count <= 0");
        return false;
    }

    if (peers_count > WIREGUARD_MAX_PEERS)
    {
        LOGF("JSON Error: WireGuardDevice->settings->peers (array field) : peers_count > WIREGUARD_MAX_PEERS");
        return false;
    }

    return true;
}

static bool processAllPeers(const cJSON *peers_array, wireguard_device_t *device)
{
    int peers_count = cJSON_GetArraySize(peers_array);
    
    for (int i = 0; i < peers_count; i++)
    {
        cJSON *peer_object = cJSON_GetArrayItem(peers_array, i);
        if (!checkJsonIsObjectAndHasChild(peer_object))
        {
            LOGF("JSON Error: WireGuardDevice->settings->peers (array of objects field) index %d : The data was empty or invalid", i);
            return false;
        }

        if (!processPeer(peer_object, device, i))
        {
            return false;
        }
    }

    return true;
}

static void wireguarddeviceInit(wireguard_device_t *device, wireguard_device_init_data_t *data)
{
    assert(data != NULL);

    wireguardInit();

    if (!validatePrivateKeyLength((char *) data->private_key))
    {
        terminateProgram(1);
    }

    if (!decodeAndInitializeDevice(device, (char *) data->private_key))
    {
        terminateProgram(1);
    }
}

tunnel_t *wireguarddeviceTunnelCreate(node_t *node)
{
    tunnel_t *t = createBaseTunnel(node);
    wgd_tstate_t *state = tunnelGetState(t);
    char *device_private_key = NULL;

    const cJSON *settings = node->node_settings_json;

    if (!checkJsonIsObjectAndHasChild(settings))
    {
        LOGF("JSON Error: WireGuardDevice->settings (object field) : The object was empty or invalid");
        return NULL;
    }

    if (!getStringFromJsonObject(&device_private_key, node->node_settings_json, "privatekey"))
    {
        LOGF("JSON Error: WireGuardDevice->settings->privatekey (string field) : The data was empty or invalid");
        return NULL;
    }

    wireguard_device_init_data_t device_configuration = {0};
    device_configuration.private_key = (const uint8_t *) device_private_key;
    state->device_configuration = device_configuration;

    wireguard_device_t *device = &state->wg_device;
    wireguarddeviceInit(device, &state->device_configuration);

    const cJSON *peers_array = cJSON_GetObjectItemCaseSensitive(settings, "peers");
    
    if (!validatePeersArray(peers_array))
    {
        return NULL;
    }

    if (!processAllPeers(peers_array, device))
    {
        return NULL;
    }

    return t;
}
