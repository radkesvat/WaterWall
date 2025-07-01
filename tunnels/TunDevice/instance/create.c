#include "structure.h"

#include "loggers/network_logger.h"

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

    t->onPrepair = &tundeviceTunnelOnPrepair;
    t->onStart   = &tundeviceTunnelOnStart;
    t->onDestroy = &tundeviceTunnelDestroy;

    tundevice_tstate_t *state = tunnelGetState(t);

    const cJSON *settings = node->node_settings_json;

    if (! checkJsonIsObjectAndHasChild(settings))
    {
        LOGF("JSON Error: TcpListener->settings (object field) : The object was empty or invalid");
        return NULL;
    }

    if (! getStringFromJsonObject(&(state->name), settings, "device-name"))
    {
        LOGF("JSON Error: TunDevice->settings->device-name (string field) : The data was empty or invalid");
        return NULL;
    }

    if (! getStringFromJsonObject(&(state->ip_subnet), settings, "device-ip"))
    {
        LOGF("JSON Error: TunDevice->settings->device-name (string field) : The data was empty or invalid");
        return NULL;
    }

    if (! verifyIPCdir(state->ip_subnet))
    {
        LOGF("TunDevice: verifyIPCdir failed, check the ip and subnet that you given");
        return NULL;
    }

    char *slash       = strchr(state->ip_subnet, '/');
    slash[0]          = 0x0;
    state->ip_present = stringDuplicate(state->ip_subnet);
    slash[0]          = '/';
    char *subnet_part = slash + 1;

    state->subnet_mask = atoi(subnet_part);

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

    return t;
}
