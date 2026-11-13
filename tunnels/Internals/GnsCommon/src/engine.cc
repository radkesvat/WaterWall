#include "GnsCommon/engine.h"

#include <steam/isteamnetworkingutils.h>
#include <steam/steamnetworkingsockets.h>

#include <cstdio>
#include <mutex>

namespace
{

enum
{
    kOptionSlots       = 12,
    kReceiveBatch      = 32,
    kSendBufferMaximum = 0x10000000, /* the library's largest SendBufferSize */
};

/* Every call into the library waits for its global lock, and a worker holds that lock while it processes a
 * datagram. Short waits are ordinary here; only a long one is worth a line in the log. */
constexpr SteamNetworkingMicroseconds kLockWaitWarningUsec = 1000 * 1000;

std::mutex          g_lock; /* guards the user count and the start and stop of the library */
int                 g_users = 0;
gns_engine_log_fn   g_log   = nullptr;
gns_engine_admit_fn g_admit = nullptr;

void onLibraryOutput(ESteamNetworkingSocketsDebugOutputType type, const char *text)
{
    if (g_log == nullptr)
    {
        return;
    }
    if (type <= k_ESteamNetworkingSocketsDebugOutputType_Error)
    {
        g_log(kGnsEngineLogError, text);
    }
    else if (type == k_ESteamNetworkingSocketsDebugOutputType_Important)
    {
        g_log(kGnsEngineLogWarning, text);
    }
    else
    {
        g_log(kGnsEngineLogDebug, text);
    }
}

/* The library reports an incoming connection only here. Everything later is read from the connection itself, so
 * the callback is cleared on it and the library queues nothing more for it. */
void onStatusChanged(SteamNetConnectionStatusChangedCallback_t *change)
{
    if (change->m_info.m_eState != k_ESteamNetworkingConnectionState_Connecting ||
        change->m_info.m_hListenSocket == k_HSteamListenSocket_Invalid)
    {
        return;
    }
    ISteamNetworkingSockets *sockets = SteamNetworkingSockets();
    void                    *none    = nullptr;
    SteamNetworkingUtils()->SetConfigValue(k_ESteamNetworkingConfig_Callback_ConnectionStatusChanged,
                                           k_ESteamNetworkingConfig_Connection,
                                           (intptr_t) change->m_hConn,
                                           k_ESteamNetworkingConfig_Ptr,
                                           &none);
    if (g_admit == nullptr || ! g_admit(change->m_info.m_nUserData, change->m_hConn) ||
        sockets->AcceptConnection(change->m_hConn) != k_EResultOK)
    {
        sockets->CloseConnection(change->m_hConn, 0, nullptr, false);
    }
}

SteamNetworkingIPAddr libraryAddress(const gns_external_addr_t &address)
{
    SteamNetworkingIPAddr result;
    result.Clear();
    result.SetIPv6(address.ip, address.port);
    return result;
}

int fillOptions(SteamNetworkingConfigValue_t *values, const gns_engine_options_t &options)
{
    int count = 0;
    values[count++].SetInt32(k_ESteamNetworkingConfig_MTU_PacketSize, options.packet_size);
    values[count++].SetInt32(k_ESteamNetworkingConfig_SendRateMin, options.send_rate);
    values[count++].SetInt32(k_ESteamNetworkingConfig_SendRateMax, options.send_rate);
    values[count++].SetInt32(k_ESteamNetworkingConfig_TimeoutInitial, options.timeout_initial_ms);
    values[count++].SetInt32(k_ESteamNetworkingConfig_TimeoutConnected, options.timeout_connected_ms);
    values[count++].SetInt32(k_ESteamNetworkingConfig_RecvMaxMessageSize, options.receive_message_max);
    values[count++].SetInt32(k_ESteamNetworkingConfig_RecvBufferSize, options.receive_buffer);
    values[count++].SetInt32(k_ESteamNetworkingConfig_RecvBufferMessages, options.receive_messages);
    /* The caller bounds what it queues and what is unacknowledged. The library's own bound must not come first. */
    values[count++].SetInt32(k_ESteamNetworkingConfig_SendBufferSize, kSendBufferMaximum);
    return count;
}

} // namespace

bool gnsEngineAcquire(gns_engine_log_fn log, gns_engine_admit_fn admit, char *error, size_t error_capacity)
{
    std::lock_guard<std::mutex> guard(g_lock);
    if (g_users == 0)
    {
        g_log   = log;
        g_admit = admit;
        SteamNetworkingErrMsg message;
        if (! GameNetworkingSockets_Init(nullptr, message))
        {
            if (error != nullptr && error_capacity > 0)
            {
                std::snprintf(error, error_capacity, "%s", message);
            }
            g_log   = nullptr;
            g_admit = nullptr;
            return false;
        }
        SteamNetworkingUtils()->SetDebugOutputFunction(k_ESteamNetworkingSocketsDebugOutputType_Warning,
                                                       onLibraryOutput);
        SteamNetworkingSockets_SetLockWaitWarningThreshold(kLockWaitWarningUsec);
    }
    ++g_users;
    return true;
}

void gnsEngineRelease(void)
{
    std::lock_guard<std::mutex> guard(g_lock);
    if (g_users > 0 && --g_users == 0)
    {
        GameNetworkingSockets_Kill();
        g_log   = nullptr;
        g_admit = nullptr;
    }
}

uint32_t gnsEngineListen(const gns_external_addr_t *local, const gns_engine_options_t *options, int64_t token)
{
    SteamNetworkingConfigValue_t values[kOptionSlots];
    int                          count = fillOptions(values, *options);
    /* Both are inherited by the connection that the listen socket accepts. */
    values[count++].SetInt64(k_ESteamNetworkingConfig_ConnectionUserData, token);
    values[count++].SetPtr(k_ESteamNetworkingConfig_Callback_ConnectionStatusChanged, (void *) onStatusChanged);
    return SteamNetworkingSockets()->CreateListenSocketIP(libraryAddress(*local), count, values);
}

void gnsEngineCloseListen(uint32_t listen_socket)
{
    SteamNetworkingSockets()->CloseListenSocket(listen_socket);
}

uint32_t gnsEngineConnect(const gns_external_addr_t *remote, const gns_engine_options_t *options)
{
    SteamNetworkingConfigValue_t values[kOptionSlots];
    const int                    count = fillOptions(values, *options);
    return SteamNetworkingSockets()->ConnectByIPAddress(libraryAddress(*remote), count, values);
}

void gnsEngineRunAccepts(void)
{
    SteamNetworkingSockets()->RunCallbacks();
}

void gnsEngineStatus(uint32_t connection, gns_engine_status_t *status)
{
    *status = gns_engine_status_t{};
    SteamNetConnectionRealTimeStatus_t now;
    if (connection == k_HSteamNetConnection_Invalid ||
        SteamNetworkingSockets()->GetConnectionRealTimeStatus(connection, &now, 0, nullptr) != k_EResultOK)
    {
        return; /* kGnsEngineGone */
    }
    switch (now.m_eState)
    {
    case k_ESteamNetworkingConnectionState_Connecting:
    case k_ESteamNetworkingConnectionState_FindingRoute:
        status->state = kGnsEngineConnecting;
        break;
    case k_ESteamNetworkingConnectionState_Connected:
        status->state = kGnsEngineConnected;
        break;
    case k_ESteamNetworkingConnectionState_ClosedByPeer:
        status->state = kGnsEngineClosedByPeer;
        break;
    case k_ESteamNetworkingConnectionState_ProblemDetectedLocally:
        status->state = kGnsEngineFailed;
        break;
    default:
        return; /* closed by this side: the handle is no longer the application's */
    }
    status->queued_bytes       = (uint32_t) now.m_cbPendingReliable;
    status->unacked_bytes      = (uint32_t) now.m_cbSentUnackedReliable;
    status->ping_ms            = now.m_nPing > 0 ? (uint32_t) now.m_nPing : 0;
    status->packets_per_second = now.m_flOutPacketsPerSec > 0 ? (uint32_t) now.m_flOutPacketsPerSec : 0;
}

gns_engine_send_t gnsEngineSend(uint32_t connection, const uint8_t *data, uint32_t length)
{
    const EResult result = SteamNetworkingSockets()->SendMessageToConnection(
        connection, data, length, k_nSteamNetworkingSend_Reliable, nullptr);
    if (result == k_EResultOK)
    {
        return kGnsEngineSendAccepted;
    }
    return result == k_EResultLimitExceeded ? kGnsEngineSendRefused : kGnsEngineSendFailed;
}

int gnsEngineReceive(uint32_t connection, gns_engine_message_t *messages, int capacity)
{
    SteamNetworkingMessage_t *taken[kReceiveBatch];
    const int                 count = SteamNetworkingSockets()->ReceiveMessagesOnConnection(
        connection, taken, capacity < kReceiveBatch ? capacity : kReceiveBatch);
    for (int i = 0; i < count; ++i)
    {
        messages[i].data   = static_cast<const uint8_t *>(taken[i]->m_pData);
        messages[i].size   = (uint32_t) taken[i]->m_cbSize;
        messages[i].handle = taken[i];
    }
    return count > 0 ? count : 0;
}

void gnsEngineMessagesRelease(gns_engine_message_t *messages, int count)
{
    for (int i = 0; i < count; ++i)
    {
        static_cast<SteamNetworkingMessage_t *>(messages[i].handle)->Release();
    }
}

void gnsEngineClose(uint32_t connection)
{
    SteamNetworkingSockets()->CloseConnection(connection, 0, nullptr, false);
}

int gnsEngineEndReason(uint32_t connection, char *text, size_t capacity)
{
    if (text != nullptr && capacity > 0)
    {
        text[0] = 0;
    }
    SteamNetConnectionInfo_t info;
    if (! SteamNetworkingSockets()->GetConnectionInfo(connection, &info))
    {
        return 0;
    }
    if (text != nullptr && capacity > 0)
    {
        std::snprintf(text, capacity, "%s", info.m_szEndDebug);
    }
    return info.m_eEndReason;
}
