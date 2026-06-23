#include "structure.h"

#include "loggers/network_logger.h"

static bool tundeviceDnsServerIsValidIpv4(const char *ip)
{
    struct in_addr addr;
    return ip != NULL && inet_pton(AF_INET, ip, &addr) == 1;
}

bool tundeviceLoadDnsSettings(tundevice_tstate_t *state, const cJSON *settings)
{
    const cJSON *dns = cJSON_GetObjectItemCaseSensitive(settings, "dns");
    if (dns == NULL || cJSON_IsNull(dns))
    {
        return true;
    }

#ifdef OS_DARWIN
    LOGF("JSON Error: TunDevice->settings->dns is not supported on macOS; use post-up-script/pre-down-script");
    return false;
#endif

    if (! cJSON_IsArray(dns))
    {
        LOGF("JSON Error: TunDevice->settings->dns must be an array of IPv4 strings");
        return false;
    }

    int dns_count = cJSON_GetArraySize(dns);
    if (dns_count <= 0 || dns_count > kTunDeviceMaxDnsServers)
    {
        LOGF("JSON Error: TunDevice->settings->dns must contain 1 to %d IPv4 addresses", kTunDeviceMaxDnsServers);
        return false;
    }

    const cJSON *entry = NULL;
    cJSON_ArrayForEach(entry, dns)
    {
        if (! cJSON_IsString(entry) || entry->valuestring == NULL || entry->valuestring[0] == '\0')
        {
            LOGF("JSON Error: TunDevice->settings->dns must contain only non-empty IPv4 strings");
            return false;
        }

        if (! tundeviceDnsServerIsValidIpv4(entry->valuestring))
        {
            LOGF("JSON Error: TunDevice->settings->dns contains invalid IPv4 address: %s", entry->valuestring);
            return false;
        }

        state->dns_servers[state->dns_server_count] = stringDuplicate(entry->valuestring);
        state->dns_server_count++;
    }

    return true;
}

bool tundeviceApplyDnsSettings(tundevice_tstate_t *state)
{
    if (state->dns_server_count == 0)
    {
        return true;
    }

    assert(state->tdev != NULL);

    const char *dns_servers[kTunDeviceMaxDnsServers];
    for (size_t i = 0; i < state->dns_server_count; ++i)
    {
        dns_servers[i] = state->dns_servers[i];
    }

    if (! tundeviceSetDnsServers(state->tdev, dns_servers, state->dns_server_count))
    {
        return false;
    }

    state->dns_servers_installed = true;
    return true;
}

void tundeviceCleanupDnsSettings(tundevice_tstate_t *state)
{
    if (! state->dns_servers_installed || state->tdev == NULL)
    {
        return;
    }

    if (! tundeviceClearDnsServers(state->tdev))
    {
        LOGW("TunDevice: failed to clear DNS servers");
    }

    state->dns_servers_installed = false;
}

void tundeviceFreeDnsSettings(tundevice_tstate_t *state)
{
    tundeviceCleanupDnsSettings(state);

    for (size_t i = 0; i < state->dns_server_count; ++i)
    {
        memoryFree(state->dns_servers[i]);
        state->dns_servers[i] = NULL;
    }

    state->dns_server_count      = 0;
    state->dns_servers_installed = false;
}
