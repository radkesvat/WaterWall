#include "tun.h"

#include "buffer_pool.h"
#include "global_state.h"
#include "managers/signal_manager.h"
#include "master_pool.h"
#include "wchan.h"
#include "wintun.h"
#include "wplatform.h"
#include "wproc.h"
#include <ctype.h>
#include <errno.h>
#include <iphlpapi.h>
#include <netioapi.h>

#include <tchar.h>

#include "loggers/internal_logger.h"


enum
{
    kTunWriteChannelQueueMax    = 1024,
    kMaxReadDistributeQueueSize = 128
};

// External variables
extern unsigned char wintun_dll[];
extern unsigned int  wintun_dll_len;

// Function pointers for Wintun functions
static WINTUN_CREATE_ADAPTER_FUNC             *WintunCreateAdapter;
static WINTUN_CLOSE_ADAPTER_FUNC              *WintunCloseAdapter;
static WINTUN_OPEN_ADAPTER_FUNC               *WintunOpenAdapter;
static WINTUN_GET_ADAPTER_LUID_FUNC           *WintunGetAdapterLUID;
static WINTUN_GET_RUNNING_DRIVER_VERSION_FUNC *WintunGetRunningDriverVersion;
static WINTUN_DELETE_DRIVER_FUNC              *WintunDeleteDriver;
static WINTUN_SET_LOGGER_FUNC                 *WintunSetLogger;
static WINTUN_START_SESSION_FUNC              *WintunStartSession;
static WINTUN_END_SESSION_FUNC                *WintunEndSession;
static WINTUN_GET_READ_WAIT_EVENT_FUNC        *WintunGetReadWaitEvent;
static WINTUN_RECEIVE_PACKET_FUNC             *WintunReceivePacket;
static WINTUN_RELEASE_RECEIVE_PACKET_FUNC     *WintunReleaseReceivePacket;
static WINTUN_ALLOCATE_SEND_PACKET_FUNC       *WintunAllocateSendPacket;
static WINTUN_SEND_PACKET_FUNC                *WintunSendPacket;

static uint16_t tunDeviceMtu(const tun_device_t *tdev)
{
    return tdev->mtu > 0 ? tdev->mtu : GLOBAL_MTU_SIZE;
}

static bool tunWindowsSetMtu(tun_device_t *tdev)
{
    NET_LUID    luid;
    NET_IFINDEX index;
    MIB_IFROW   if_row;

    if (tdev->adapter_handle == NULL)
    {
        LOGE("TunDevice: Cannot set MTU -> No Adapter!");
        return false;
    }

    WintunGetAdapterLUID(tdev->adapter_handle, &luid);

    NETIO_STATUS status = ConvertInterfaceLuidToIndex(&luid, &index);
    if (status != NO_ERROR)
    {
        LOGE("TunDevice: failed to resolve adapter interface index, code: %lu", status);
        return false;
    }

    memorySet(&if_row, 0, sizeof(if_row));
    if_row.dwIndex = index;
    DWORD last_error = GetIfEntry(&if_row);
    if (last_error != NO_ERROR)
    {
        LOGE("TunDevice: failed to query adapter interface row, code: %lu", last_error);
        return false;
    }

    if_row.dwMtu = tunDeviceMtu(tdev);
    last_error = SetIfEntry(&if_row);
    if (last_error != NO_ERROR)
    {
        LOGE("TunDevice: failed to set adapter MTU, code: %lu", last_error);
        return false;
    }

    return true;
}

static bool routeTableIsMain(const char *route_table)
{
    return route_table == NULL || stringCompare(route_table, "main") == 0 || stringCompare(route_table, "auto") == 0;
}

static bool tunWindowsParseRouteCidr(const char *cidr, SOCKADDR_INET *addr, UINT8 *prefix)
{
    if (cidr == NULL || cidr[0] == '\0')
    {
        return false;
    }

    const char *slash = stringChr(cidr, '/');
    if (slash == NULL || slash == cidr || slash[1] == '\0')
    {
        return false;
    }

    size_t ip_len = (size_t) (slash - cidr);
    if (ip_len >= INET6_ADDRSTRLEN)
    {
        return false;
    }

    char ip_part[INET6_ADDRSTRLEN];
    memoryCopy(ip_part, cidr, ip_len);
    ip_part[ip_len] = '\0';

    errno         = 0;
    char *end_ptr = NULL;
    long  prefix_l = strtol(slash + 1, &end_ptr, 10);
    if (errno != 0 || end_ptr == slash + 1 || *end_ptr != '\0')
    {
        return false;
    }

    memorySet(addr, 0, sizeof(*addr));
    if (inet_pton(AF_INET, ip_part, &addr->Ipv4.sin_addr) == 1)
    {
        if (prefix_l < 0 || prefix_l > 32)
        {
            return false;
        }
        addr->Ipv4.sin_family = AF_INET;
        *prefix               = (UINT8) prefix_l;
        return true;
    }

    if (inet_pton(AF_INET6, ip_part, &addr->Ipv6.sin6_addr) == 1)
    {
        if (prefix_l < 0 || prefix_l > 128)
        {
            return false;
        }
        addr->Ipv6.sin6_family = AF_INET6;
        *prefix                = (UINT8) prefix_l;
        return true;
    }

    return false;
}

/**
 * Writes the Wintun DLL bytes to a temporary file on disk
 * @param dllBytes Pointer to the DLL binary data
 * @param dllSize Size of the DLL data in bytes
 * @return Path to the temporary file or NULL on failure
 */
static TCHAR *writeDllToTempFile(const unsigned char *dllBytes, size_t dllSize)
{
    TCHAR tempPath[MAX_PATH];
    TCHAR tempFileName[MAX_PATH];

    // Get the system's temporary directory
    if (GetTempPath(MAX_PATH, tempPath) == 0)
    {
        LOGE("TunDevice: Failed to get temporary path");
        return NULL;
    }

    // Generate a unique temporary file name
    if (GetTempFileName(tempPath, _T("dll"), 0, tempFileName) == 0)
    {
        LOGE("TunDevice: Failed to create temporary filename");
        return NULL;
    }

    // Open the temporary file for writing
    HANDLE hFile = CreateFile(tempFileName, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        LOGE("TunDevice: Failed to create temporary file");
        return NULL;
    }

    // Write the DLL bytes to the file
    DWORD bytesWritten;
    if (! WriteFile(hFile, dllBytes, (DWORD) dllSize, &bytesWritten, NULL) || bytesWritten != (DWORD) dllSize)
    {
        LOGE("TunDevice: Failed to write temporary file");
        CloseHandle(hFile);
        DeleteFile(tempFileName);
        return NULL;
    }

    // Close the file handle
    CloseHandle(hFile);

    // Return the path to the temporary file
    return _tcsdup(tempFileName);
}

/**
 * Initializes the Windows TUN device system
 * Loads the Wintun DLL and required functions
 */
static void tunWindowsStartup(void)
{
    // Write the embedded DLL to a temporary file
    TCHAR *tempDllPath = writeDllToTempFile(&wintun_dll[0], wintun_dll_len);
    if (! tempDllPath)
    {
        LOGE("TunDevice: Failed to write DLL to temporary file");
        return;
    }

    // Convert TCHAR path to wide string and load the DLL
    WCHAR widePath[MAX_PATH];
    MultiByteToWideChar(CP_ACP, 0, tempDllPath, -1, widePath, MAX_PATH);
    HMODULE hModule = LoadLibraryExW(widePath, NULL, 0);
    if (! hModule)
    {
        LOGE("TunDevice: Failed to load DLL: error %lu", GetLastError());
        DeleteFile(tempDllPath);
        free(tempDllPath);
        return;
    }

    LOGD("TunDevice: DLL loaded successfully");

    GSTATE.wintun_dll_handle = hModule;
    DeleteFile(tempDllPath);
    free(tempDllPath);
}

/**
 * Event message structure for TUN device communication
 */
struct msg_event
{
    tun_device_t *tdev;
    sbuf_t       *bufs[kMaxReadDistributeQueueSize];
    uint8_t       count;
};

// Allocate memory for message pool handle
static pool_item_t *allocTunMsgPoolHandle(master_pool_t *pool, void *userdata)
{
    discard userdata;
    discard pool;
    return memoryAllocate(sizeof(struct msg_event));
}

// Free memory for message pool handle
static void destroyTunMsgPoolHandle(master_pool_t *pool, master_pool_item_t *item, void *userdata)
{
    discard pool;
    discard userdata;
    memoryFree(item);
}

/**
 * Handles events received on the local thread
 * @param ev Event containing message data
 */
static void localThreadEventReceived(wevent_t *ev)
{
    struct msg_event *msg = weventGetUserdata(ev);
    wid_t             wid = (wid_t) (wloopGetWid(weventGetLoop(ev)));

    for (unsigned int i = 0; i < msg->count; i++)
    {
        msg->tdev->read_event_callback(msg->tdev, msg->tdev->userdata, msg->bufs[i], wid);
    }

    masterpoolReuseItems(msg->tdev->reader_message_pool, (void **) &msg, 1, msg->tdev);
}

/**
 * Distributes a packet payload to the target worker thread
 * @param tdev TUN device handle
 * @param target_wid Target thread ID
 * @param buf Buffer containing packet data
 */
static void distributePacketPayloads(tun_device_t *tdev, wid_t target_wid, sbuf_t **buf, unsigned int queued_count)
{
    struct msg_event *msg;
    masterpoolGetItems(tdev->reader_message_pool, (const void **) &(msg), 1, tdev);

    msg->tdev  = tdev;
    msg->count = queued_count;
    for (unsigned int i = 0; i < queued_count; i++)
    {
        msg->bufs[i] = buf[i];
    }

    wevent_t ev;
    memorySet(&ev, 0, sizeof(ev));
    ev.loop = getWorkerLoop(target_wid);
    ev.cb   = localThreadEventReceived;
    weventSetUserData(&ev, msg);
    if (UNLIKELY(false == wloopPostEvent(getWorkerLoop(target_wid), &ev)))
    {
        for (unsigned int i = 0; i < queued_count; i++)
        {
            bufferpoolReuseBuffer(tdev->reader_buffer_pool, msg->bufs[i]);
        }
        masterpoolReuseItems(tdev->reader_message_pool, (void **) &msg, 1, tdev);
    }
}
// {
//     struct msg_event *msg;
//     masterpoolGetItems(tdev->reader_message_pool, (const void **) &(msg), 1, tdev);

//     *msg = (struct msg_event){.tdev = tdev, .buf = buf};

//     wevent_t ev;
//     memorySet(&ev, 0, sizeof(ev));
//     ev.loop = getWorkerLoop(target_wid);
//     ev.cb   = localThreadEventReceived;
//     weventSetUserData(&ev, msg);
//     wloopPostEvent(getWorkerLoop(target_wid), &ev);
// }

/**
 * Reader thread routine - reads packets from TUN device
 */
static WTHREAD_ROUTINE(routineReadFromTun)
{
    tun_device_t         *tdev    = userdata;
    WINTUN_SESSION_HANDLE Session = tdev->session_handle;
    sbuf_t               *bufs[kMaxReadDistributeQueueSize];
    uint8_t               queued_count = 0;

    while (atomicLoadRelaxed(&(tdev->running)))
    {
        bufs[queued_count] = bufferpoolGetSmallBuffer(tdev->reader_buffer_pool);
        bufs[queued_count] = sbufReserveSpace(bufs[queued_count], tunDeviceMtu(tdev));

        DWORD packet_size;
        BYTE *packet = WintunReceivePacket(Session, &packet_size);

        if (packet)
        {
            if (UNLIKELY(packet_size > tunDeviceMtu(tdev)))
            {
                LOGE("TunDevice: ReadThread: read packet size %lu exceeds device MTU %u", packet_size,
                     tunDeviceMtu(tdev));
                WintunReleaseReceivePacket(Session, packet);
                bufferpoolReuseBuffer(tdev->reader_buffer_pool, bufs[queued_count]);

                for (unsigned int i = 0; i < queued_count; i++)
                {
                    bufferpoolReuseBuffer(tdev->reader_buffer_pool, bufs[i]);
                }
                LOGF("TunDevice: This is related to the MTU size, please set a correct value for TunDevice "
                     "'device-mtu'");
                terminateProgram(1);
            }

            sbufSetLength(bufs[queued_count], packet_size);
            memoryCopyLarge(sbufGetMutablePtr(bufs[queued_count]), packet, packet_size);

            WintunReleaseReceivePacket(Session, packet);

            if (TUN_LOG_EVERYTHING)
            {
                LOGD("TunDevice: ReadThread: Read %lu bytes from device %s", packet_size, tdev->name);
                // printPacket(Packet, PacketSize);
            }

            if (queued_count < kMaxReadDistributeQueueSize - 1)
            {
                queued_count++;
            }
            else
            {
                distributePacketPayloads(tdev, getNextDistributionWID(), &bufs[0], queued_count + 1);
                queued_count = 0;
            }
        }
        else
        {

            bufferpoolReuseBuffer(tdev->reader_buffer_pool, bufs[queued_count]);

            DWORD last_error = GetLastError();
            switch (last_error)
            {
            // i dont know why it can happen when debugging with gdb
            case ERROR_ENVVAR_NOT_FOUND:
                continue;
            break;
            // case ERROR_NO_MORE_ITEMS:
            case ERROR_NO_MORE_ITEMS:
                if (queued_count > 0)
                {
                    distributePacketPayloads(tdev, getNextDistributionWID(), &bufs[0], queued_count);
                    queued_count = 0;
                    continue;
                }
                HANDLE wait_handle = WintunGetReadWaitEvent(Session);
            wait:;
                DWORD wait_result = WaitForSingleObject(wait_handle, 500);
                if (wait_result == WAIT_OBJECT_0)
                {
                    continue;
                }
                if (wait_result == WAIT_TIMEOUT)
                {
                    // when it times out we check atomic value to exit read routine if requsted

                    MemoryBarrier();
                    if (atomicLoadRelaxed(&(tdev->running)) == false)
                    {
                        return 0;
                    }

                    goto wait;
                }
                return ERROR_SUCCESS;
            default:
                LOGE("TunDevice: ReadThread: Packet read failed: error %lu", last_error);
                LOGE("TunDevice: ReadThread: Terminating");
                return last_error;
            }
        }
    }
    LOGD("TunDevice: ReadThread: Terminating due to not running");

    return 0;
}

/**
 * Writer thread routine - writes packets to TUN device
 */
static WTHREAD_ROUTINE(routineWriteToTun)
{
    tun_device_t         *tdev    = userdata;
    WINTUN_SESSION_HANDLE Session = tdev->session_handle;
    sbuf_t               *buf;
    MemoryBarrier();

    while (atomicLoadRelaxed(&(tdev->running)))
    {
        if (! chanRecv(tdev->writer_buffer_channel, (void **) &buf))
        {
            LOGD("TunDevice: WriteThread: Terminating due to closed channel");
            return 0;
        }

        if (UNLIKELY(tunDeviceMtu(tdev) < sbufGetLength(buf)))
        {
            LOGW("TunDevice: WriteThread: discarded a packet -> size %d exceeds device MTU %u", sbufGetLength(buf),
                 tunDeviceMtu(tdev));

            bufferpoolReuseBuffer(tdev->writer_buffer_pool, buf);
            continue;
        }

        BYTE *Packet = WintunAllocateSendPacket(Session, sbufGetLength(buf));
        if (! Packet)
        {
            bufferpoolReuseBuffer(tdev->writer_buffer_pool, buf);

            if (GetLastError() != ERROR_BUFFER_OVERFLOW)
            {
                LOGE("TunDevice: WriteThread: Failed to allocate memory for write packet, WinTun Ring Overflow");
            }
            else
            {
                LOGE("TunDevice: WriteThread: Failed to allocate memory for write packet %lu", GetLastError());
                LOGE("TunDevice: WriteThread: Terminating");
                return 0;
            }
            continue;
        }

        memoryCopyLarge(Packet, sbufGetRawPtr(buf), sbufGetLength(buf));

        WintunSendPacket(Session, Packet);

        bufferpoolReuseBuffer(tdev->writer_buffer_pool, buf);
    }

    LOGD("TunDevice: WriteThread: Terminating due to not running");

    return 0;
}

bool tundeviceBringUp(tun_device_t *tdev)
{
    if (tdev->up)
    {
        LOGE("TunDevice: Device is already up");
        return false;
    }

    bufferpoolUpdateAllocationPaddings(tdev->reader_buffer_pool,
                                       bufferpoolGetLargeBufferPadding(getWorkerBufferPool(getWID())),
                                       bufferpoolGetSmallBufferPadding(getWorkerBufferPool(getWID())));

    bufferpoolUpdateAllocationPaddings(tdev->writer_buffer_pool,
                                       bufferpoolGetLargeBufferPadding(getWorkerBufferPool(getWID())),
                                       bufferpoolGetSmallBufferPadding(getWorkerBufferPool(getWID())));

    if (! tunWindowsSetMtu(tdev))
    {
        LOGE("TunDevice: error setting MTU size");
        return false;
    }

    tdev->writer_buffer_channel = chanOpen(sizeof(void *), kTunWriteChannelQueueMax);
    MemoryBarrier();

    LOGI("TunDevice: Starting WinTun session");
    WINTUN_SESSION_HANDLE Session = WintunStartSession(tdev->adapter_handle, 0x400000);
    if (! Session)
    {
        DWORD lastError = GetLastError();
        LOGE("TunDevice: Failed to start session, code: %lu", lastError);
        chanClose(tdev->writer_buffer_channel);
        chanFree(tdev->writer_buffer_channel);
        tdev->writer_buffer_channel = NULL;
        return false;
    }

    tdev->up = true;
    atomicStoreRelaxed(&(tdev->running), true);
    tdev->session_handle = Session;

    MemoryBarrier();

    tdev->read_thread  = threadCreate(tdev->routine_reader, tdev);
    tdev->write_thread = threadCreate(tdev->routine_writer, tdev);
    return true;
}

bool tundeviceBringDown(tun_device_t *tdev)
{
    if (! tdev->up)
    {
        LOGE("TunDevice: Device is already down");
        return true;
    }

    atomicStoreRelaxed(&(tdev->running), false);
    tdev->up = false;
    MemoryBarrier();

    WintunEndSession(tdev->session_handle);

    chanClose(tdev->writer_buffer_channel);

    safeThreadJoin(tdev->read_thread);
    safeThreadJoin(tdev->write_thread);

    sbuf_t *buf;
    while (chanRecv(tdev->writer_buffer_channel, (void *) &buf))
    {
        bufferpoolReuseBuffer(tdev->writer_buffer_pool, buf);
    }
    chanFree(tdev->writer_buffer_channel);
    tdev->writer_buffer_channel = NULL;

    assert(tdev->session_handle != NULL);
    LOGI("TunDevice: Ending WinTun session");
    tdev->session_handle = NULL;

    return true;
}

bool tundeviceAssignIP(tun_device_t *tdev, const char *ip_presentation, unsigned int subnet)
{
    if (tdev->adapter_handle == NULL)
    {
        LOGE("TunDevice: Cannot set IP -> No Adapter!");
        return false;
    }

    if (tdev->session_handle != NULL)
    {
        LOGE("TunDevice: Cannot set IP -> Session already started");
        return false;
    }

    MIB_UNICASTIPADDRESS_ROW *AddressRow = &tdev->address_row;
    InitializeUnicastIpAddressEntry(AddressRow);
    WintunGetAdapterLUID(tdev->adapter_handle, &AddressRow->InterfaceLuid);

    if (inet_pton(AF_INET, ip_presentation, &AddressRow->Address.Ipv4.sin_addr) == 1)
    {
        if (subnet > 32)
        {
            LOGE("TunDevice: Cannot set IP -> Invalid IPv4 prefix: %u", subnet);
            return false;
        }
        AddressRow->Address.Ipv4.sin_family = AF_INET;
    }
    else if (inet_pton(AF_INET6, ip_presentation, &AddressRow->Address.Ipv6.sin6_addr) == 1)
    {
        if (subnet > 128)
        {
            LOGE("TunDevice: Cannot set IP -> Invalid IPv6 prefix: %u", subnet);
            return false;
        }
        AddressRow->Address.Ipv6.sin6_family = AF_INET6;
    }
    else
    {
        LOGE("TunDevice: Cannot set IP -> Invalid IP address: %s", ip_presentation);
        return false;
    }

    AddressRow->OnLinkPrefixLength = (uint8_t) subnet;
    AddressRow->DadState           = IpDadStatePreferred;
    DWORD LastError                = CreateUnicastIpAddressEntry(AddressRow);
    if (LastError != ERROR_SUCCESS && LastError != ERROR_OBJECT_ALREADY_EXISTS)
    {
        LOGE("TunDevice: Failed to set IP address, code: %lu", LastError);
        return false;
    }
    return true;
}

bool tundeviceUnAssignIP(tun_device_t *tdev, const char *ip_presentation, unsigned int subnet)
{
    if (tdev->adapter_handle == NULL)
    {
        LOGE("TunDevice: Cannot unset IP -> No Adapter!");
        return false;
    }

    if (tdev->session_handle != NULL)
    {
        LOGE("TunDevice: Cannot unset IP -> Session already started");
        return false;
    }

    MIB_UNICASTIPADDRESS_ROW *AddressRow = &tdev->address_row;
    InitializeUnicastIpAddressEntry(AddressRow);
    WintunGetAdapterLUID(tdev->adapter_handle, &AddressRow->InterfaceLuid);
    if (inet_pton(AF_INET, ip_presentation, &AddressRow->Address.Ipv4.sin_addr) == 1)
    {
        if (subnet > 32)
        {
            LOGE("TunDevice: Cannot unset IP -> Invalid IPv4 prefix: %u", subnet);
            return false;
        }
        AddressRow->Address.Ipv4.sin_family = AF_INET;
    }
    else if (inet_pton(AF_INET6, ip_presentation, &AddressRow->Address.Ipv6.sin6_addr) == 1)
    {
        if (subnet > 128)
        {
            LOGE("TunDevice: Cannot unset IP -> Invalid IPv6 prefix: %u", subnet);
            return false;
        }
        AddressRow->Address.Ipv6.sin6_family = AF_INET6;
    }
    else
    {
        LOGE("TunDevice: Cannot unset IP -> Invalid IP address: %s", ip_presentation);
        return false;
    }

    AddressRow->OnLinkPrefixLength = (uint8_t) subnet;
    DWORD LastError                = DeleteUnicastIpAddressEntry(AddressRow);
    if (LastError != ERROR_SUCCESS && LastError != ERROR_NOT_FOUND)
    {
        LOGE("TunDevice: Failed to unassign IP address, code: %lu", LastError);
        return false;
    }
    return true;
}

bool tundeviceAddRoute(tun_device_t *tdev, const char *cidr, const char *route_table)
{
    if (! routeTableIsMain(route_table))
    {
        LOGE("TunDevice: route-table '%s' is not supported on Windows", route_table);
        return false;
    }

    if (tdev->adapter_handle == NULL)
    {
        LOGE("TunDevice: Cannot add route -> No Adapter!");
        return false;
    }

    SOCKADDR_INET prefix_addr;
    UINT8         prefix_len;
    if (! tunWindowsParseRouteCidr(cidr, &prefix_addr, &prefix_len))
    {
        LOGE("TunDevice: invalid route CIDR: %s", cidr);
        return false;
    }

    MIB_IPFORWARD_ROW2 row;
    InitializeIpForwardEntry(&row);
    WintunGetAdapterLUID(tdev->adapter_handle, &row.InterfaceLuid);
    row.DestinationPrefix.Prefix       = prefix_addr;
    row.DestinationPrefix.PrefixLength = prefix_len;
    row.NextHop.si_family              = prefix_addr.si_family;
    row.Protocol                       = MIB_IPPROTO_NETMGMT;
    row.Metric                         = 0;
    row.ValidLifetime                  = 0xFFFFFFFF;
    row.PreferredLifetime              = 0xFFFFFFFF;

    NETIO_STATUS status = CreateIpForwardEntry2(&row);
    if (status != NO_ERROR)
    {
        LOGE("TunDevice: failed to add system route %s, code: %lu", cidr, status);
        return false;
    }

    LOGI("TunDevice: added system route %s on %s", cidr, tdev->name);
    return true;
}

bool tundeviceRemoveRoute(tun_device_t *tdev, const char *cidr, const char *route_table)
{
    if (! routeTableIsMain(route_table))
    {
        LOGE("TunDevice: route-table '%s' is not supported on Windows", route_table);
        return false;
    }

    if (tdev->adapter_handle == NULL)
    {
        LOGE("TunDevice: Cannot remove route -> No Adapter!");
        return false;
    }

    SOCKADDR_INET prefix_addr;
    UINT8         prefix_len;
    if (! tunWindowsParseRouteCidr(cidr, &prefix_addr, &prefix_len))
    {
        LOGE("TunDevice: invalid route CIDR: %s", cidr);
        return false;
    }

    MIB_IPFORWARD_ROW2 row;
    InitializeIpForwardEntry(&row);
    WintunGetAdapterLUID(tdev->adapter_handle, &row.InterfaceLuid);
    row.DestinationPrefix.Prefix       = prefix_addr;
    row.DestinationPrefix.PrefixLength = prefix_len;
    row.NextHop.si_family              = prefix_addr.si_family;

    NETIO_STATUS status = DeleteIpForwardEntry2(&row);
    if (status != NO_ERROR && status != ERROR_NOT_FOUND)
    {
        LOGE("TunDevice: failed to remove system route %s, code: %lu", cidr, status);
        return false;
    }

    LOGI("TunDevice: removed system route %s on %s", cidr, tdev->name);
    return true;
}

bool tundeviceWrite(tun_device_t *tdev, sbuf_t *buf)
{
    // minimum length of an IP header is 20 bytes
    assert(sbufGetLength(buf) > 20);

    bool closed = false;
    if (! chanTrySend(tdev->writer_buffer_channel, (void *) &buf, &closed))
    {
        if (closed)
        {
            LOGE("TunDevice: Write failed, channel was closed");
        }
        else
        {
            LOGE("TunDevice: Write failed, ring is full");
        }
        return false;
    }
    return true;
}

// just destroy this device on tunnel destroy handle
// /**
//  * Handles exit signal and cleans up TUN device
//  * @param userdata User data (TUN device handle)
//  * @param signum Signal number
//  */
// static void exitHandle(void *userdata, int signum)
// {
//     // Sleep(2200);
//     // LOGW("called close handle");
//     discard       signum;
//     tun_device_t *tdev = userdata;
//     if (tdev->up)
//     {
//         tundeviceBringDown(tdev);
//     }

//     assert(tdev->session_handle == NULL);

//     if (tdev->adapter_handle)
//     {
//         WintunCloseAdapter(tdev->adapter_handle);
//         tdev->adapter_handle = NULL;
//     }
//     // Sleep(2200);
// }

// Function to load a function pointer from a DLL
static bool loadFunctionFromDLL(const char *function_name, void *target)
{
    FARPROC proc = GetProcAddress(GSTATE.wintun_dll_handle, function_name);
    if (proc == NULL)
    {
        LOGE("TunDevice: Error: Failed to load function '%s' from WinTun DLL.", function_name);
        return false;
    }
    memoryCopy(target, &proc, sizeof(FARPROC));
    return true;
}

tun_device_t *tundeviceCreate(const char *name, bool offload, uint16_t mtu, void *userdata, TunReadEventHandle cb)
{
    discard offload;
    DWORD   LastError;

    if (! GSTATE.flag_tundev_windows_initialized)
    {
        tunWindowsStartup();
        GSTATE.flag_tundev_windows_initialized = true;
    }

    if (GSTATE.wintun_dll_handle == NULL)
    {
        LOGE("TunDevice: Wintun DLL not loaded");
        return NULL;
    }

    // Load each function pointer and check for NULL
    if (! loadFunctionFromDLL("WintunCreateAdapter", &WintunCreateAdapter))
        return NULL;
    if (! loadFunctionFromDLL("WintunCloseAdapter", &WintunCloseAdapter))
        return NULL;
    if (! loadFunctionFromDLL("WintunOpenAdapter", &WintunOpenAdapter))
        return NULL;
    if (! loadFunctionFromDLL("WintunGetAdapterLUID", &WintunGetAdapterLUID))
        return NULL;
    if (! loadFunctionFromDLL("WintunGetRunningDriverVersion", &WintunGetRunningDriverVersion))
        return NULL;
    if (! loadFunctionFromDLL("WintunDeleteDriver", &WintunDeleteDriver))
        return NULL;
    if (! loadFunctionFromDLL("WintunSetLogger", &WintunSetLogger))
        return NULL;
    if (! loadFunctionFromDLL("WintunStartSession", &WintunStartSession))
        return NULL;
    if (! loadFunctionFromDLL("WintunEndSession", &WintunEndSession))
        return NULL;
    if (! loadFunctionFromDLL("WintunGetReadWaitEvent", &WintunGetReadWaitEvent))
        return NULL;
    if (! loadFunctionFromDLL("WintunReceivePacket", &WintunReceivePacket))
        return NULL;
    if (! loadFunctionFromDLL("WintunReleaseReceivePacket", &WintunReleaseReceivePacket))
        return NULL;
    if (! loadFunctionFromDLL("WintunAllocateSendPacket", &WintunAllocateSendPacket))
        return NULL;
    if (! loadFunctionFromDLL("WintunSendPacket", &WintunSendPacket))
        return NULL;

    LOGI("TunDevice: WinTun loaded successfully");

    uint32_t worker_large_buffer_size = bufferpoolGetLargeBufferSize(getWorkerBufferPool(getWID()));
    uint32_t worker_small_buffer_size = bufferpoolGetSmallBufferSize(getWorkerBufferPool(getWID()));
    worker_small_buffer_size          = max(worker_small_buffer_size, (uint32_t) mtu);

    buffer_pool_t *reader_bpool =
        bufferpoolCreate(GSTATE.masterpool_buffer_pools_large, GSTATE.masterpool_buffer_pools_small, RAM_PROFILE,

                         worker_large_buffer_size,
                         worker_small_buffer_size

        );

    buffer_pool_t *writer_bpool =
        bufferpoolCreate(GSTATE.masterpool_buffer_pools_large, GSTATE.masterpool_buffer_pools_small, RAM_PROFILE,

                         worker_large_buffer_size,
                         worker_small_buffer_size

        );

    tun_device_t *tdev = memoryAllocate(sizeof(tun_device_t));

    *tdev = (tun_device_t){
        .name                  = stringDuplicate(name),
        .running               = false,
        .up                    = false,
        .routine_reader        = routineReadFromTun,
        .routine_writer        = routineWriteToTun,
        .read_event_callback   = cb,
        .userdata              = userdata,
        .writer_buffer_channel = NULL,
        .reader_message_pool   = masterpoolCreateWithCapacity(RAM_PROFILE * 2),
        .reader_buffer_pool    = reader_bpool,
        .writer_buffer_pool    = writer_bpool,
        .adapter_handle        = NULL,
        .session_handle        = NULL,
        .mtu                   = mtu,
        .packets_queued        = 0,
    };

    masterpoolInstallCallBacks(tdev->reader_message_pool, allocTunMsgPoolHandle, destroyTunMsgPoolHandle);

    int wide_size = MultiByteToWideChar(CP_UTF8, 0, name, -1, NULL, 0);
    if (wide_size <= 0)
    {
        LOGE("TunDevice: Failed to calculate UTF-16 length for adapter name");
        tundeviceDestroy(tdev);
        return NULL;
    }

    tdev->name_w = (wchar_t *) memoryAllocate(wide_size * sizeof(wchar_t));
    if (! tdev->name_w)
    {
        LOGE("TunDevice: Memory allocation failed!");
        tundeviceDestroy(tdev);
        return NULL;
    }

    if (MultiByteToWideChar(CP_UTF8, 0, name, -1, (tdev->name_w), wide_size) <= 0)
    {
        LOGE("TunDevice: Failed to convert adapter name to UTF-16");
        tundeviceDestroy(tdev);
        return NULL;
    }

    WINTUN_ADAPTER_HANDLE adapter = WintunCreateAdapter(tdev->name_w, L"Waterwall Adapter", NULL);
    if (! adapter)
    {
        LastError = GetLastError();
        LOGE("TunDevice: Failed to create adapter! code: %lu", LastError);
        tundeviceDestroy(tdev);
        return NULL;
    }
    tdev->adapter_handle = adapter;

    return tdev;
}

/**
 * Destroys the TUN device and releases resources
 * @param tdev TUN device handle
 * the creator worker thread has to call this function
 */
void tundeviceDestroy(tun_device_t *tdev)
{

    if (tdev->up)
    {
        tundeviceBringDown(tdev);
    }

    assert(tdev->session_handle == NULL);

    if (tdev->adapter_handle)
    {

        WintunCloseAdapter(tdev->adapter_handle);
        tdev->adapter_handle = NULL;
    }

    memoryFree(tdev->name);
    memoryFree(tdev->name_w);
    bufferpoolDestroy(tdev->reader_buffer_pool);
    bufferpoolDestroy(tdev->writer_buffer_pool);
    masterpoolMakeEmpty(tdev->reader_message_pool, NULL);
    masterpoolDestroy(tdev->reader_message_pool);

    memoryFree(tdev);
}
