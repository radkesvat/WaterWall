#include "structure.h"

#include "loggers/network_logger.h"

static tunnel_t *tundeviceTunnelCreateFail(tunnel_t *t)
{
    tundeviceTunnelDestroy(t);
    return NULL;
}

static void tundevicePublishEgressPinIfNeeded(tundevice_tstate_t *state)
{
    if (! state->loop_protection_enabled || state->egress_pin_published)
    {
        return;
    }

    tun_default_route_t route;
    if (tundeviceDetectDefaultInterface(&route))
    {
        egressPinSet(route.ifname, route.have_v4 ? route.ifindex_v4 : 0, route.have_v6 ? route.ifindex_v6 : 0);
        state->egress_pin_published = true;
    }
    else
    {
        LOGW("TunDevice: could not detect default interface; self-loop protection inactive "
             "(configure connector interface_name or route-exclude-cidrs manually)");
    }
}

tunnel_t *tundeviceTunnelCreate(node_t *node)
{
    tunnel_t *t = tunnelCreate(node, sizeof(tundevice_tstate_t), sizeof(tundevice_lstate_t));

    t->fnInitU    = &tundeviceTunnelUpStreamInit;
    t->fnEstU     = &tundeviceTunnelUpStreamEst;
    t->fnFinU     = &tundeviceTunnelUpStreamFinish;
    t->fnPayloadU = &tundeviceTunnelUpStreamPayload;
    t->fnPauseU   = &tundeviceTunnelUpStreamPause;
    t->fnResumeU  = &tundeviceTunnelUpStreamResume;

    t->fnInitD    = &tundeviceTunnelDownStreamInit;
    t->fnEstD     = &tundeviceTunnelDownStreamEst;
    t->fnFinD     = &tundeviceTunnelDownStreamFinish;
    t->fnPayloadD = &tundeviceTunnelDownStreamPayload;
    t->fnPauseD   = &tundeviceTunnelDownStreamPause;
    t->fnResumeD  = &tundeviceTunnelDownStreamResume;

    t->onPrepare = &tundeviceTunnelOnPrepair;
    t->onStart   = &tundeviceTunnelOnStart;
    t->onStop    = &tundeviceTunnelOnStop;
    t->onDestroy = &tundeviceTunnelDestroy;

    tundevice_tstate_t *state = tunnelGetState(t);

    const cJSON *settings = node->node_settings_json;

    if (! checkJsonIsObjectAndHasChild(settings))
    {
        LOGF("JSON Error: TunDevice->settings (object field) : The object was empty or invalid");
        return tundeviceTunnelCreateFail(t);
    }

    if (! getStringFromJsonObject(&(state->name), settings, "device-name"))
    {
        LOGF("JSON Error: TunDevice->settings->device-name (string field) : The data was empty or invalid");
        return tundeviceTunnelCreateFail(t);
    }

    if (! getStringFromJsonObject(&(state->ip_subnet), settings, "device-ip"))
    {
        LOGF("JSON Error: TunDevice->settings->device-ip (string field) : The data was empty or invalid");
        return tundeviceTunnelCreateFail(t);
    }

    ip_addr_t parsed_ip;
    ip_addr_t parsed_mask;
    uint8_t   parsed_prefix = 0;
    int parsed_family = parseIPWithSubnetMaskAndPrefix(state->ip_subnet, &parsed_ip, &parsed_mask, &parsed_prefix);
    if (parsed_family != 4 && parsed_family != 6)
    {
        LOGF("TunDevice: device-ip must be a valid IPv4 or IPv6 CIDR");
        return tundeviceTunnelCreateFail(t);
    }

    const char *slash  = stringChr(state->ip_subnet, '/');
    size_t      ip_len = (size_t) (slash - state->ip_subnet);
    state->ip_present  = memoryAllocate(ip_len + 1U);
    memoryCopy(state->ip_present, state->ip_subnet, ip_len);
    state->ip_present[ip_len] = '\0';

    state->subnet_mask = (int) parsed_prefix;

    int dev_mtu = 0;
    getIntFromJsonObjectOrDefault(&dev_mtu, settings, "device-mtu", GLOBAL_MTU_SIZE);
    if (dev_mtu <= 0 || dev_mtu > UINT16_MAX)
    {
        LOGF("JSON Error: TunDevice->settings->device-mtu must be between 1 and %u", UINT16_MAX);
        return tundeviceTunnelCreateFail(t);
    }

    state->mtu = dev_mtu;

    if (! tundeviceLoadRouteSettings(state, settings))
    {
        return tundeviceTunnelCreateFail(t);
    }

    if (! tundeviceLoadDnsSettings(state, settings))
    {
        return tundeviceTunnelCreateFail(t);
    }

    // tun creation must be done in prepair or start padding, in create method paddings are not calculated yout

    // on windows we need admin to load win tun driver
    const char *fail_msg = "Error: Loading the WireGuard driver requires administrative privileges.\n\n"
                           "Please restart Waterwall as an administrator and try again.";
#ifdef OS_WIN
    if (! isAdmin())
    {
        MessageBox(NULL, fail_msg, "Error", MB_OK | MB_ICONERROR);
        terminateProgram(1);
    }
    // if (! elevatePrivileges(
    //         FINAL_EXECUTABLE_NAME,
    //         fail_msg))
    // {
    //     terminateProgram(1);
    // }
#else
    discard fail_msg;
#endif

    // Publish before any tunnel OnPrepare creates sockets. Route installation
    // still happens in OnStart, so this snapshots the pre-TUN default interface.
    tundevicePublishEgressPinIfNeeded(state);

    return t;
}
