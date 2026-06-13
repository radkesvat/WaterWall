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
    size_t  private_key_len = sizeof(dummy_key);

    if (BASE64_ENCODE_OUT_SIZE(private_key_len) != stringLength((char *) private_key))
    {
        LOGE("Error: WireGuardDevice->settings->privatekey (string field) : The data was empty or invalid");
        return false;
    }
    return true;
}

static bool decodeOptionalPresharedKey(const char *preshared_key_b64, uint8_t *decoded_key)
{
    if (preshared_key_b64 == NULL)
    {
        return true;
    }

    if (stringLength(preshared_key_b64) != BASE64_ENCODE_OUT_SIZE(WIREGUARD_SESSION_KEY_LEN))
    {
        return false;
    }

    return wwBase64Decode(preshared_key_b64, (unsigned int) stringLength(preshared_key_b64), decoded_key) ==
           WIREGUARD_SESSION_KEY_LEN;
}

static bool decodeAndInitializeDevice(wireguard_device_t *device, const char *private_key)
{
    uint8_t decoded_key[WIREGUARD_PRIVATE_KEY_LEN];

    if (wwBase64Decode((char *) private_key, (unsigned int) stringLength((char *) private_key), decoded_key) !=
        WIREGUARD_PRIVATE_KEY_LEN)
    {
        return false;
    }

    if (! wireguardDeviceInit(device, decoded_key))
    {
        return false;
    }

    device->status_connected = 0;
    return true;
}

static tunnel_t *createBaseTunnel(node_t *node)
{
    tunnel_t *t = packettunnelCreate(node, sizeof(wgd_tstate_t), 0);
    if (t == NULL)
    {
        return NULL;
    }

    t->fnInitD      = &wireguarddeviceTunnelDownStreamInit;
    t->fnPayloadU   = &wireguarddeviceTunnelUpStreamPayload;
    t->fnPayloadD   = &wireguarddeviceTunnelDownStreamPayload;
    t->onPrepare    = &wireguarddeviceTunnelOnPrepair;
    t->onStart      = &wireguarddeviceTunnelOnStart;
    t->onStop       = &wireguarddeviceTunnelOnStop;
    t->onWorkerStop = &wireguarddeviceTunnelOnWorkerStop;
    t->onDestroy    = &wireguarddeviceTunnelDestroy;

    wgd_tstate_t *state = tunnelGetState(t);
    state->tunnel       = t;
    mutexInit(&state->mutex);

    return t;
}

static bool parseAllowedIps(const char *allowed_ips, ip_addr_t *allowed_ip_list, ip_addr_t *allowed_mask_list,
                            uint8_t *allowed_ip_count, int peer_index)
{
    char *allowed_ips_nospace = stringNewWithoutSpace(allowed_ips);

    if ((allowed_ips_nospace == NULL) || (allowed_ips_nospace[0] == '\0'))
    {
        memoryFree(allowed_ips_nospace);
        return false;
    }

    uint8_t count  = 0;
    char   *cursor = allowed_ips_nospace;

    while (cursor != NULL)
    {
        char *comma_ptr = stringChr(cursor, ',');
        if (comma_ptr != NULL)
        {
            *comma_ptr = '\0';
        }

        if ((cursor[0] == '\0') || (! verifyIPCdir(cursor)))
        {
            LOGF("JSON Error: WireGuardDevice->settings->peers [ index %d  ]->allowedips entry is invalid", peer_index);
            memoryFree(allowed_ips_nospace);
            return false;
        }

        if (count >= WIREGUARD_MAX_SRC_IPS)
        {
            LOGF("JSON Error: WireGuardDevice->settings->peers [ index %d  ]->allowedips exceeds WIREGUARD_MAX_SRC_IPS",
                 peer_index);
            memoryFree(allowed_ips_nospace);
            return false;
        }

        if (parseIPWithSubnetMask(cursor, &allowed_ip_list[count], &allowed_mask_list[count]) == ERR_ARG)
        {
            LOGF("JSON Error: WireGuardDevice->settings->peers [ index %d  ]->allowedips entry could not be parsed",
                 peer_index);
            memoryFree(allowed_ips_nospace);
            return false;
        }

        count++;
        cursor = (comma_ptr != NULL) ? (comma_ptr + 1) : NULL;
    }

    *allowed_ip_count = count;
    memoryFree(allowed_ips_nospace);
    return count > 0;
}

static bool parseEndpoint(const char *endpoint, wireguard_peer_init_data_t *peer)
{
    char *endpoint_copy = stringDuplicate(endpoint);
    char *host_ptr      = endpoint_copy;
    char *colon_ptr;

    if ((endpoint_copy == NULL) || (endpoint_copy[0] == '\0'))
    {
        memoryFree(endpoint_copy);
        return false;
    }

    if (endpoint_copy[0] == '[')
    {
        char *closing_bracket = stringChr(endpoint_copy, ']');

        if ((closing_bracket == NULL) || (closing_bracket[1] != ':'))
        {
            memoryFree(endpoint_copy);
            return false;
        }

        *closing_bracket = '\0';
        host_ptr         = endpoint_copy + 1;
        colon_ptr        = closing_bracket + 1;
    }
    else
    {
        colon_ptr = strrchr(endpoint_copy, ':');
        if (colon_ptr == NULL)
        {
            memoryFree(endpoint_copy);
            return false;
        }
    }

    *colon_ptr = '\0';

    char *endpoint_port = colon_ptr + 1;
    long  parsed_port   = atol(endpoint_port);

    if ((host_ptr[0] == '\0') || (parsed_port <= 0) || (parsed_port > UINT16_MAX))
    {
        memoryFree(endpoint_copy);
        return false;
    }

    sockaddr_u temp;
    if (resolveAddr(host_ptr, &temp) != 0)
    {
        memoryFree(endpoint_copy);
        return false;
    }

    if (! sockaddrToIpAddr(&temp, &peer->endpoint_ip))
    {
        memoryFree(endpoint_copy);
        return false;
    }

    peer->endpoint_port = (uint16_t) parsed_port;

    memoryFree(endpoint_copy);
    return true;
}

static bool extractPeerFields(cJSON *peer_object, char **public_key, char **preshared_key, char **allowed_ips,
                              char **endpoint, int *keepalive, int peer_index)
{
    if (! getStringFromJsonObject(public_key, peer_object, "publickey"))
    {
        LOGF("JSON Error: WireGuardDevice->settings->peers [ index %d  ]->publickey (string field) : The data was "
             "empty or invalid",
             peer_index);
        return false;
    }

    getStringFromJsonObject(preshared_key, peer_object, "presharedkey");

    if (! getStringFromJsonObject(allowed_ips, peer_object, "allowedips"))
    {
        LOGF("JSON Error: WireGuardDevice->settings->peers [ index %d  ]->allowedips (string field) : The data was "
             "empty or invalid",
             peer_index);
        return false;
    }

    if (! getStringFromJsonObject(endpoint, peer_object, "endpoint"))
    {
        LOGF("JSON Error: WireGuardDevice->settings->peers [ index %d  ]->endpoint (string field) : The data was empty "
             "or invalid",
             peer_index);
        return false;
    }

    getIntFromJsonObject(keepalive, peer_object, "persistentkeepalive");
    return true;
}

static bool processPeer(cJSON *peer_object, wireguard_device_t *device, int peer_index)
{
    char     *peer_public_key      = NULL;
    char     *peer_preshared_key   = NULL;
    char     *peer_allowed_ips     = NULL;
    char     *peer_endpoint        = NULL;
    int       persistentkeepalive  = 0;
    bool      ok                   = false;
    uint8_t   peer_index_on_device = WIREGUARDIF_INVALID_INDEX;
    uint8_t   allowed_ip_count     = 0;
    ip_addr_t allowed_ip_list[WIREGUARD_MAX_SRC_IPS];
    ip_addr_t allowed_mask_list[WIREGUARD_MAX_SRC_IPS];
    uint8_t   decoded_preshared_key[WIREGUARD_SESSION_KEY_LEN];

    if (! extractPeerFields(peer_object,
                            &peer_public_key,
                            &peer_preshared_key,
                            &peer_allowed_ips,
                            &peer_endpoint,
                            &persistentkeepalive,
                            peer_index))
    {
        return false;
    }

    wireguard_peer_init_data_t peer = {0};
    wireguardifPeerInit(&peer);
    peer.public_key = (const uint8_t *) peer_public_key;

    if ((persistentkeepalive < 0) || (persistentkeepalive > UINT16_MAX))
    {
        LOGF("JSON Error: WireGuardDevice->settings->peers [ index %d  ]->persistentkeepalive must be between 0 and "
             "65535",
             peer_index);
        goto cleanup;
    }

    peer.keep_alive = (uint16_t) persistentkeepalive;

    if (! parseEndpoint(peer_endpoint, &peer))
    {
        goto cleanup;
    }

    if (! parseAllowedIps(peer_allowed_ips, allowed_ip_list, allowed_mask_list, &allowed_ip_count, peer_index))
    {
        goto cleanup;
    }

    peer.allowed_ip   = allowed_ip_list[0];
    peer.allowed_mask = allowed_mask_list[0];

    if (! decodeOptionalPresharedKey(peer_preshared_key, decoded_preshared_key))
    {
        LOGF("JSON Error: WireGuardDevice->settings->peers [ index %d  ]->presharedkey must be a base64-encoded "
             "32-byte key",
             peer_index);
        goto cleanup;
    }

    if (peer_preshared_key != NULL)
    {
        peer.preshared_key = decoded_preshared_key;
    }

    if (wireguardifAddPeer(device, &peer, &peer_index_on_device) != ERR_OK)
    {
        LOGF("Error: wireguardifAddPeer failed");
        goto cleanup;
    }

    for (uint8_t i = 1; i < allowed_ip_count; ++i)
    {
        if (wireguardifAddAllowedIp(device, peer_index_on_device, &allowed_ip_list[i], &allowed_mask_list[i]) != ERR_OK)
        {
            LOGF("Error: wireguardifAddAllowedIp failed");
            wireguardifRemovePeer(device, peer_index_on_device);
            goto cleanup;
        }
    }

    ok = true;

cleanup:
    if (peer_public_key != NULL)
    {
        memoryFree(peer_public_key);
    }
    if (peer_preshared_key != NULL)
    {
        memoryFree(peer_preshared_key);
    }
    if (peer_allowed_ips != NULL)
    {
        memoryFree(peer_allowed_ips);
    }
    if (peer_endpoint != NULL)
    {
        memoryFree(peer_endpoint);
    }
    wCryptoZero(decoded_preshared_key, sizeof(decoded_preshared_key));
    return ok;
}

static bool validatePeersArray(const cJSON *peers_array)
{
    if (! cJSON_IsArray(peers_array))
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
        if (! checkJsonIsObjectAndHasChild(peer_object))
        {
            LOGF("JSON Error: WireGuardDevice->settings->peers (array of objects field) index %d : The data was empty "
                 "or invalid",
                 i);
            return false;
        }

        if (! processPeer(peer_object, device, i))
        {
            return false;
        }
    }

    return true;
}

static bool parseTransportDirection(wgd_tstate_t *state, const cJSON *settings)
{
    const cJSON *direction = cJSON_GetObjectItemCaseSensitive(settings, "transport-direction");

    if (direction == NULL)
    {
        return true;
    }

    if (! cJSON_IsString(direction) || direction->valuestring == NULL)
    {
        LOGF("JSON Error: WireGuardDevice->settings->transport-direction must be \"next\"/\"up\" or "
             "\"prev\"/\"down\"");
        return false;
    }

    if (stringCompare(direction->valuestring, "next") == 0 || stringCompare(direction->valuestring, "up") == 0 ||
        stringCompare(direction->valuestring, "upstream") == 0)
    {
        state->transport_side_is_next         = true;
        state->transport_direction_configured = true;
        return true;
    }

    if (stringCompare(direction->valuestring, "prev") == 0 || stringCompare(direction->valuestring, "down") == 0 ||
        stringCompare(direction->valuestring, "downstream") == 0)
    {
        state->transport_side_is_next         = false;
        state->transport_direction_configured = true;
        return true;
    }

    LOGF("JSON Error: WireGuardDevice->settings->transport-direction must be \"next\"/\"up\" or "
         "\"prev\"/\"down\"");
    return false;
}

static void wireguarddeviceInit(wireguard_device_t *device, wireguard_device_init_data_t *data)
{
    assert(data != NULL);

    wireguardInit();

    if (! validatePrivateKeyLength((char *) data->private_key))
    {
        terminateProgram(1);
    }

    if (! decodeAndInitializeDevice(device, (char *) data->private_key))
    {
        terminateProgram(1);
    }
}

tunnel_t *wireguarddeviceTunnelCreate(node_t *node)
{
    tunnel_t *t = createBaseTunnel(node);
    if (t == NULL)
    {
        return NULL;
    }

    wgd_tstate_t *state              = tunnelGetState(t);
    char         *device_private_key = NULL;

    const cJSON *settings = node->node_settings_json;

    if (! checkJsonIsObjectAndHasChild(settings))
    {
        LOGF("JSON Error: WireGuardDevice->settings (object field) : The object was empty or invalid");
        goto fail;
    }

    if (! getStringFromJsonObject(&device_private_key, node->node_settings_json, "privatekey"))
    {
        LOGF("JSON Error: WireGuardDevice->settings->privatekey (string field) : The data was empty or invalid");
        goto fail;
    }

    if (! parseTransportDirection(state, settings))
    {
        goto fail;
    }

    wireguard_device_init_data_t device_configuration = {0};
    device_configuration.private_key                  = (const uint8_t *) device_private_key;
    state->device_configuration                       = device_configuration;

    wireguard_device_t *device = &state->wg_device;
    wireguarddeviceInit(device, &state->device_configuration);

    const cJSON *peers_array = cJSON_GetObjectItemCaseSensitive(settings, "peers");

    if (! validatePeersArray(peers_array))
    {
        goto fail;
    }

    if (! processAllPeers(peers_array, device))
    {
        goto fail;
    }

    return t;

fail:
    wireguarddeviceTunnelDestroy(t);
    return NULL;
}
