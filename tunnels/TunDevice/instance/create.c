#include "structure.h"

#include "loggers/network_logger.h"

#include <limits.h>

static tunnel_t *tundeviceTunnelCreateFail(tunnel_t *t)
{
    tundeviceTunnelDestroy(t, wwLifecycleStartupRollback());
    return NULL;
}

static void tundevicePublishEgressPinIfNeeded(tundevice_tstate_t *state)
{
    assert(! state->egress_pin_published);
    if (! state->loop_protection_enabled)
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
    tunnel_t *t = packettunnelCreate(node, sizeof(tundevice_tstate_t), 0);
    if (! t)
    {
        return NULL;
    }

    t->onStart          = &tundeviceTunnelOnStart;
    t->onQuiesceRequest = &tundeviceTunnelOnQuiesceRequest;
    t->onWorkerQuiesce  = &tundeviceTunnelOnWorkerQuiesce;
    t->onQuiesceWait    = &tundeviceTunnelOnQuiesceWait;
    t->onDestroy        = &tundeviceTunnelDestroy;

    const packet_lifecycle_anchor_direction_t direction =
        node->hash_next != 0 ? kPacketLifecycleAnchorPublishUpstream : kPacketLifecycleAnchorPublishDownstream;
    if (! packettunnelConfigureLifecycleAnchor(t, "TunDevice", tundeviceTunnelWritePayload, direction))
    {
        tunnelDestroy(t);
        return NULL;
    }

    tundevice_tstate_t *state = tunnelGetState(t);
#ifdef OS_WIN
    state->windows_ownership = (tun_windows_ownership_t) {0};
#endif

    const cJSON *settings = node->node_settings_json;

    if (! packettunnelReadFragmentPolicy(settings, &state->fragment_policy))
    {
        return tundeviceTunnelCreateFail(t);
    }

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
    if (parsed_family != 4)
    {
        LOGF("TunDevice: device-ip must be a valid IPv4 CIDR");
        return tundeviceTunnelCreateFail(t);
    }

    const char *slash  = stringChr(state->ip_subnet, '/');
    size_t      ip_len = (size_t) (slash - state->ip_subnet);
    state->ip_present  = memoryAllocate(ip_len + 1U);
    memoryCopy(state->ip_present, state->ip_subnet, ip_len);
    state->ip_present[ip_len] = '\0';

    state->subnet_mask = (int) parsed_prefix;

    int64_t             dev_mtu    = CORE_DEFAULT_MTU;
    json_value_status_t mtu_status = jsonGetObjectIntegerInRange(settings, "device-mtu", 68, UINT16_MAX, &dev_mtu);
    if (mtu_status == kJsonValueInvalid || dev_mtu < 68 || dev_mtu > UINT16_MAX)
    {
        LOGF("JSON Error: TunDevice->settings->device-mtu must be an integer between 68 and %u%s",
             UINT16_MAX,
             mtu_status == kJsonValueMissing ? "; inherited core misc.mtu is unsupported; set an explicit device-mtu"
                                             : "");
        return tundeviceTunnelCreateFail(t);
    }

    state->mtu = (uint16_t) dev_mtu;

    state->gso_requested = true;
    if (jsonGetObjectBoolean(settings, "gso", &state->gso_requested) == kJsonValueInvalid)
    {
        LOGF("JSON Error: TunDevice->settings->gso must be a boolean");
        return tundeviceTunnelCreateFail(t);
    }

    state->multi_queue_requested = true;
    if (jsonGetObjectBoolean(settings, "multi-queue", &state->multi_queue_requested) == kJsonValueInvalid)
    {
        LOGF("JSON Error: TunDevice->settings->multi-queue must be a boolean");
        return tundeviceTunnelCreateFail(t);
    }

#ifdef OS_LINUX
    state->kernel_queue_tune = true;
#else
    state->kernel_queue_tune = false;
#endif
    if (jsonGetObjectBoolean(settings, "kernel-queue-tune", &state->kernel_queue_tune) == kJsonValueInvalid)
    {
        LOGF("JSON Error: TunDevice->settings->kernel-queue-tune must be a boolean");
        return tundeviceTunnelCreateFail(t);
    }
    int64_t kernel_queue_length = 0;
    if (jsonGetObjectIntegerInRange(settings, "kernel-queue-length", 1, INT_MAX, &kernel_queue_length) ==
        kJsonValueInvalid)
    {
        LOGF("JSON Error: TunDevice->settings->kernel-queue-length must be an integer between 1 and %d", INT_MAX);
        return tundeviceTunnelCreateFail(t);
    }
    state->kernel_queue_length = (uint32_t) kernel_queue_length;

    if (! tundeviceLoadRouteSettings(state, settings))
    {
        return tundeviceTunnelCreateFail(t);
    }

    if (! tundeviceLoadDnsSettings(state, settings))
    {
        return tundeviceTunnelCreateFail(t);
    }

    /* Device creation waits for OnStart, after chain padding is finalized. */
#ifdef OS_WIN
    const char *fail_msg = "Error: Loading the Wintun driver requires administrative privileges.\n\n"
                           "Please restart Waterwall as an administrator and try again.";
    if (! isAdmin())
    {
        if (configPolicyIsRestricted())
        {
            LOGE("TunDevice: administrative driver capability is unavailable");
        }
        else
        {
            MessageBox(NULL, fail_msg, "Error", MB_OK | MB_ICONERROR);
        }
        startupFailureRecord(1);
        return tundeviceTunnelCreateFail(t);
    }
#endif

    // Publish before any tunnel OnPrepare creates sockets. Route installation
    // still happens in OnStart, so this snapshots the pre-TUN default interface.
#ifdef OS_WIN
    if (! tunWindowsOwnershipPrepare(state->name, &state->windows_ownership))
    {
        LOGE("TunDevice: adapter is in use, inaccessible, or could not be prepared (Windows error %lu)",
             GetLastError());
        startupFailureRecord(1);
        return tundeviceTunnelCreateFail(t);
    }
#endif
    tundevicePublishEgressPinIfNeeded(state);

    return t;
}
