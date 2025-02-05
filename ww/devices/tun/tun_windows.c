#include "global_state.h"
#include "managers/signal_manager.h"
#include "master_pool.h"
#include "buffer_pool.h"
#include "tun.h"
#include "wchan.h"
#include "wintun/wintun.h"
#include "wlibc.h"
#include <tchar.h>

#include "loggers/internal_logger.h"


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
        LOGE("Failed to get temporary path");
        return NULL;
    }

    // Generate a unique temporary file name
    if (GetTempFileName(tempPath, _T("dll"), 0, tempFileName) == 0)
    {
        LOGE("Failed to create temporary filename");
        return NULL;
    }

    // Open the temporary file for writing
    HANDLE hFile = CreateFile(tempFileName, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        LOGE("Failed to create temporary file");
        return NULL;
    }

    // Write the DLL bytes to the file
    DWORD bytesWritten;
    if (! WriteFile(hFile, dllBytes, (DWORD) dllSize, &bytesWritten, NULL))
    {
        LOGE("Failed to write temporary file");
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
        LOGE("Failed to write DLL to temporary file");
        return;
    }

    // Convert TCHAR path to wide string and load the DLL
    WCHAR widePath[MAX_PATH];
    MultiByteToWideChar(CP_ACP, 0, tempDllPath, -1, widePath, MAX_PATH);
    HMODULE hModule = LoadLibraryExW(widePath, NULL, 0);
    if (! hModule)
    {
        LOGE("Failed to load DLL: error %lu", GetLastError());
        DeleteFile(tempDllPath);
        free(tempDllPath);
        return;
    }

    LOGI("DLL loaded successfully");

    GSTATE.wintun_dll_handle = hModule;
}

/**
 * Prints details about a network packet for debugging
 * @param Packet Raw packet data
 * @param PacketSize Size of packet in bytes
 */
static void printPacket(_In_ const BYTE *Packet, _In_ DWORD PacketSize)
{
    if (PacketSize < 20)
    {
        LOGI("Packet received without IP header");
        return;
    }
    BYTE  IpVersion = Packet[0] >> 4, Proto;
    WCHAR Src[46], Dst[46];
    if (IpVersion == 4)
    {
        RtlIpv4AddressToStringW((struct in_addr *) &Packet[12], Src);
        RtlIpv4AddressToStringW((struct in_addr *) &Packet[16], Dst);
        Proto = Packet[9];
        Packet += 20, PacketSize -= 20;
    }
    else if (IpVersion == 6 && PacketSize < 40)
    {
        LOGI("Invalid packet size for IPv6 header");
        return;
    }
    else if (IpVersion == 6)
    {
        RtlIpv6AddressToStringW((struct in6_addr *) &Packet[8], Src);
        RtlIpv6AddressToStringW((struct in6_addr *) &Packet[24], Dst);
        Proto = Packet[6];
        Packet += 40, PacketSize -= 40;
    }
    else
    {
        LOGI("Non-IP packet received");
        return;
    }
    if (Proto == 1 && PacketSize >= 8 && Packet[0] == 0)
        LOGI("IPv%d ICMP echo reply from %s to %s", IpVersion, Src, Dst);
    else
        LOGI("IPv%d protocol 0x%x packet from %s to %s", IpVersion, Proto, Src, Dst);
}

/**
 * Event message structure for TUN device communication
 */
struct msg_event
{
    tun_device_t *tdev;
    sbuf_t       *buf;
};

static void PrintPacket(_In_ const BYTE *Packet, _In_ DWORD PacketSize)
{
    if (PacketSize < 20)
    {
        LOGI("Received packet without room for an IP header");
        return;
    }
    BYTE  IpVersion = Packet[0] >> 4, Proto;
    WCHAR Src[46], Dst[46];
    if (IpVersion == 4)
    {
        RtlIpv4AddressToStringW((struct in_addr *) &Packet[12], Src);
        RtlIpv4AddressToStringW((struct in_addr *) &Packet[16], Dst);
        Proto = Packet[9];
        Packet += 20, PacketSize -= 20;
    }
    else if (IpVersion == 6 && PacketSize < 40)
    {
        LOGI("Received packet without room for an IP header");
        return;
    }
    else if (IpVersion == 6)
    {
        RtlIpv6AddressToStringW((struct in6_addr *) &Packet[8], Src);
        RtlIpv6AddressToStringW((struct in6_addr *) &Packet[24], Dst);
        Proto = Packet[6];
        Packet += 40, PacketSize -= 40;
    }
    else
    {
        LOGI("Received packet that was not IP");
        return;
    }
    if (Proto == 1 && PacketSize >= 8 && Packet[0] == 0)
    {
        LOGI("Received IPv%d protocol 0x%x packet from %s to %s", IpVersion, Proto, Src, Dst);
    }
    else
    {
        LOGI("Received IPv%d proto 0x%x packet from %s to %s", IpVersion, Proto, Src, Dst);
    }
}
// Allocate memory for message pool handle
static pool_item_t *allocTunMsgPoolHandle(master_pool_t *pool, void *userdata)
{
    (void) userdata;
    (void) pool;
    return memoryAllocate(sizeof(struct msg_event));
}

// Free memory for message pool handle
static void destroyTunMsgPoolHandle(master_pool_t *pool, master_pool_item_t *item, void *userdata)
{
    (void) pool;
    (void) userdata;
    memoryFree(item);
}

/**
 * Handles events received on the local thread
 * @param ev Event containing message data
 */
static void localThreadEventReceived(wevent_t *ev)
{
    struct msg_event *msg = weventGetUserdata(ev);
    wid_t             tid = (wid_t) (wloopTID(weventGetLoop(ev)));

    msg->tdev->read_event_callback(msg->tdev, msg->tdev->userdata, msg->buf, tid);
    masterpoolReuseItems(msg->tdev->reader_message_pool, (void **) &msg, 1, msg->tdev);
}

/**
 * Distributes a packet payload to the target worker thread
 * @param tdev TUN device handle
 * @param target_tid Target thread ID
 * @param buf Buffer containing packet data
 */
static void distributePacketPayload(tun_device_t *tdev, wid_t target_tid, sbuf_t *buf)
{
    struct msg_event *msg;
    masterpoolGetItems(tdev->reader_message_pool, (const void **) &(msg), 1, tdev);

    *msg = (struct msg_event){.tdev = tdev, .buf = buf};

    wevent_t ev;
    memorySet(&ev, 0, sizeof(ev));
    ev.loop = getWorkerLoop(target_tid);
    ev.cb   = localThreadEventReceived;
    weventSetUserData(&ev, msg);
    wloopPostEvent(getWorkerLoop(target_tid), &ev);
}

/**
 * Reader thread routine - reads packets from TUN device
 */
static WTHREAD_ROUTINE(routineReadFromTun)
{
    tun_device_t         *tdev           = userdata;
    WINTUN_SESSION_HANDLE Session        = tdev->session_handle;
    HANDLE WaitHandles[] = { WintunGetReadWaitEvent(Session), tdev->quit_event };
    wid_t                 distribute_tid = 0;
    sbuf_t               *buf;
    ssize_t               nread;

    while (atomicLoadRelaxed(&(tdev->running)))
    {
        buf = bufferpoolGetSmallBuffer(tdev->reader_buffer_pool);
        assert(sbufGetRightCapacity(buf) >= kReadPacketSize);

        DWORD PacketSize;
        BYTE *Packet = WintunReceivePacket(Session, &PacketSize);
        if (Packet)
        {
            sbufSetLength(buf, PacketSize);

            if (TUN_LOG_EVERYTHING)
            {
                LOGD("Read %zd bytes from device %s", nread, tdev->name);
                // printPacket(Packet, PacketSize);
            }

            distributePacketPayload(tdev, distribute_tid++, buf);

            if (distribute_tid >= getWorkersCount())
            {
                distribute_tid = 0;
            }

            WintunReleaseReceivePacket(Session, Packet);
        }
        else
        {
            bufferpoolReuseBuffer(tdev->reader_buffer_pool, buf);

            DWORD LastError = GetLastError();
            switch (LastError)
            {
            case ERROR_NO_MORE_ITEMS:
                if (WaitForMultipleObjects(_countof(WaitHandles), WaitHandles, FALSE, INFINITE) == WAIT_OBJECT_0)
                    continue;
                return ERROR_SUCCESS;
            default:
                LOGE("ReadThread: Packet read failed: error %lu", LastError);
                LOGE("ReadThread: Terminating");
                return LastError;
            }
        }
    }
    LOGD("ReadThread: Terminating due to not running");

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

    while (atomicLoadRelaxed(&(tdev->running)))
    {
        if (! chanRecv(tdev->writer_buffer_channel, (void *) &buf))
        {
            LOGD("WriteThread: Terminating due to closed channel");
            return 0;
        }

        BYTE *Packet = WintunAllocateSendPacket(Session, sbufGetBufLength(buf));
        if (! Packet)
        {
            bufferpoolReuseBuffer(tdev->writer_buffer_pool, buf);

            if (GetLastError() != ERROR_BUFFER_OVERFLOW)
            {
                LOGE("WriteThread: Failed to allocate memory for write packet, WinTun Ring Overflow");
            }
            else
            {
                LOGE("WriteThread: Failed to allocate memory for write packet %lu", GetLastError());
                LOGE("WriteThread: Terminating");
                return 0;
            }
            continue;
        }

        memoryCopy(Packet, sbufGetRawPtr(buf), sbufGetBufLength(buf));

        WintunSendPacket(Session, Packet);

        bufferpoolReuseBuffer(tdev->writer_buffer_pool, buf);
    }

    LOGD("WriteThread: Terminating due to not running");

    return 0;
}

/**
 * Brings the TUN device up and starts the read/write threads
 * @param tdev TUN device handle
 * @return true if successful, false otherwise
 */
bool tundeviceBringUp(tun_device_t *tdev)
{
    if (tdev->up)
    {
        LOGE("Device is already up");
        return false;
    }

    tdev->writer_buffer_channel = chanOpen(sizeof(void *), kTunWriteChannelQueueMax);

    WINTUN_SESSION_HANDLE Session = WintunStartSession(tdev->adapter_handle, 0x400000);
    if (! Session)
    {
        DWORD lastError = GetLastError();
        LOGE("Failed to start session, code: %lu", lastError);
        return false;
    }

    ResetEvent(tdev->quit_event);
    tdev->up = true;
    atomicStoreRelaxed(&(tdev->running), true);
    tdev->session_handle = Session;

    MemoryBarrier();

    if (tdev->read_event_callback != NULL)
    {
        tdev->read_thread = threadCreate(tdev->routine_reader, tdev);
    }
    tdev->write_thread = threadCreate(tdev->routine_writer, tdev);
    return true;
}

/**
 * Brings the TUN device down and stops the read/write threads
 * @param tdev TUN device handle
 * @return true if successful, false otherwise
 */
bool tundeviceBringDown(tun_device_t *tdev)
{
    if (! tdev->up)
    {
        LOGE("Device is already down");
        return false;
    }

    atomicStoreRelaxed(&(tdev->running), false);
    tdev->up = false;
    SetEvent(tdev->quit_event);
    MemoryBarrier();

    chanClose(tdev->writer_buffer_channel);
    sbuf_t *buf;

    while (chanRecv(tdev->writer_buffer_channel, (void *) &buf))
    {
        bufferpoolReuseBuffer(tdev->reader_buffer_pool, buf);
    }
    tdev->writer_buffer_channel = NULL;

  

    if (tdev->read_event_callback != NULL)
    {
        threadJoin(tdev->read_thread);
    }
    threadJoin(tdev->write_thread);

    assert(tdev->session_handle != NULL);
    LOGD("Ending session");
    WintunEndSession(tdev->session_handle);
    tdev->session_handle = NULL;

    return true;
}

/**
 * Assigns an IP address to the TUN device
 * @param tdev TUN device handle
 * @param ip_presentation IP address in string format
 * @param subnet Subnet mask length
 * @return true if successful, false otherwise
 */
bool tundeviceAssignIP(tun_device_t *tdev, const char *ip_presentation, unsigned int subnet)
{
    ULONG ip_binary;
    if (! (inet_pton(AF_INET, ip_presentation, &ip_binary) == 1))
    {
        LOGE("Cannot set IP -> Invalid IP address: %s", ip_presentation);
    }

    if (tdev->adapter_handle == NULL)
    {
        LOGE("Cannot set IP -> No Adapter!");
        return false;
    }

    if (tdev->session_handle != NULL)
    {
        LOGE("Cannot set IP -> Session already started");
        return false;
    }

    MIB_UNICASTIPADDRESS_ROW *AddressRow = &tdev->address_row;
    InitializeUnicastIpAddressEntry(AddressRow);
    WintunGetAdapterLUID(tdev->adapter_handle, &AddressRow->InterfaceLuid);
    AddressRow->Address.Ipv4.sin_family           = AF_INET;
    AddressRow->Address.Ipv4.sin_addr.S_un.S_addr = ip_binary;
    AddressRow->OnLinkPrefixLength                = subnet;
    AddressRow->DadState                          = IpDadStatePreferred;
    DWORD LastError                               = CreateUnicastIpAddressEntry(AddressRow);
    if (LastError != ERROR_SUCCESS && LastError != ERROR_OBJECT_ALREADY_EXISTS)
    {
        LOGE("Failed to set IP address, code: %lu", LastError);
        return false;
    }
    return true;
}

/**
 * Unassigns an IP address from the TUN device
 * @param tdev TUN device handle
 * @param ip_presentation IP address in string format
 * @param subnet Subnet mask length
 * @return true if successful, false otherwise
 */
bool tundeviceUnAssignIP(tun_device_t *tdev, const char *ip_presentation, unsigned int subnet)
{
    (void) subnet;
    (void) ip_presentation;

    if (tdev->adapter_handle == NULL)
    {
        LOGE("Cannot set IP -> No Adapter!");
        return false;
    }

    MIB_UNICASTIPADDRESS_ROW *AddressRow = &tdev->address_row;
    InitializeUnicastIpAddressEntry(AddressRow);
    WintunGetAdapterLUID(tdev->adapter_handle, &AddressRow->InterfaceLuid);
    AddressRow->Address.Ipv4.sin_family           = AF_INET;
    AddressRow->Address.Ipv4.sin_addr.S_un.S_addr = htonl((10 << 24) | (6 << 16) | (7 << 8) | (7 << 0)); /* 10.6.7.7 */
    DWORD LastError                               = CreateUnicastIpAddressEntry(AddressRow);
    if (LastError != ERROR_SUCCESS && LastError != ERROR_OBJECT_ALREADY_EXISTS)
    {
        LOGE("Failed to unassign IP address, code: %lu", LastError);
        return false;
    }
    return true;
}

/**
 * Writes a buffer to the TUN device
 * @param tdev TUN device handle
 * @param buf Buffer containing packet data
 * @return true if successful, false otherwise
 */
bool tundeviceWrite(tun_device_t *tdev, sbuf_t *buf)
{
    // minimum length of an IP header is 20 bytes
    assert(sbufGetBufLength(buf) > 20);
    if (atomicLoadRelaxed(&(tdev->running)) == false)
    {
        LOGE("Write failed, device is not running");
        return false;
    
    }

    bool closed = false;
    if (! chanTrySend(tdev->writer_buffer_channel, (void *) &buf, &closed))
    {
        if (closed)
        {
            LOGE("Write failed, channel was closed");
        }
        else
        {
            LOGE("Write failed, ring is full");
        }
        return false;
    }
    return true;
}

/**
 * Handles exit signal and cleans up TUN device
 * @param userdata User data (TUN device handle)
 * @param signum Signal number
 */
static void exitHandle(void *userdata, int signum)
{
    Sleep(2200);
    LOGW("called close handle");
    (void) signum;
    tun_device_t *tdev = userdata;
    tundeviceDestroy(tdev);
    Sleep(2200);
}

// Function to load a function pointer from a DLL
static bool loadFunctionFromDLL(const char* function_name, void* target) {
    FARPROC proc = GetProcAddress(GSTATE.wintun_dll_handle, function_name);
    if (proc == NULL) {
        LOGE("Error: Failed to load function '%s' from WinTun DLL.", function_name);
        return false;
    }
    memoryCopy(target, &proc, sizeof(FARPROC)); 
    return true;
}

/**
 * Creates a new TUN device
 * @param name Name of the TUN device
 * @param offload Offload flag
 * @param userdata User data
 * @param cb Read event callback function
 * @return Pointer to the created TUN device or NULL on failure
 */
tun_device_t *tundeviceCreate(const char *name, bool offload, void *userdata, TunReadEventHandle cb)
{
    (void) offload;
    DWORD LastError;

    if (! GSTATE.internal_flag_tundev_windows_initialized)
    {
        tunWindowsStartup();
        GSTATE.internal_flag_tundev_windows_initialized = true;
    }

    if (GSTATE.wintun_dll_handle == NULL)
    {
        LOGE("Wintun DLL not loaded");
        return NULL;
    }


    // Load each function pointer and check for NULL
    if (!loadFunctionFromDLL("WintunCreateAdapter", &WintunCreateAdapter)) return NULL;
    if (!loadFunctionFromDLL("WintunCloseAdapter", &WintunCloseAdapter)) return NULL;
    if (!loadFunctionFromDLL("WintunOpenAdapter", &WintunOpenAdapter)) return NULL;
    if (!loadFunctionFromDLL("WintunGetAdapterLUID", &WintunGetAdapterLUID)) return NULL;
    if (!loadFunctionFromDLL("WintunGetRunningDriverVersion", &WintunGetRunningDriverVersion)) return NULL;
    if (!loadFunctionFromDLL("WintunDeleteDriver", &WintunDeleteDriver)) return NULL;
    if (!loadFunctionFromDLL("WintunSetLogger", &WintunSetLogger)) return NULL;
    if (!loadFunctionFromDLL("WintunStartSession", &WintunStartSession)) return NULL;
    if (!loadFunctionFromDLL("WintunEndSession", &WintunEndSession)) return NULL;
    if (!loadFunctionFromDLL("WintunGetReadWaitEvent", &WintunGetReadWaitEvent)) return NULL;
    if (!loadFunctionFromDLL("WintunReceivePacket", &WintunReceivePacket)) return NULL;
    if (!loadFunctionFromDLL("WintunReleaseReceivePacket", &WintunReleaseReceivePacket)) return NULL;
    if (!loadFunctionFromDLL("WintunAllocateSendPacket", &WintunAllocateSendPacket)) return NULL;
    if (!loadFunctionFromDLL("WintunSendPacket", &WintunSendPacket)) return NULL;


    LOGD("Wintun loaded successfully");

    buffer_pool_t *reader_bpool =
        bufferpoolCreate(GSTATE.masterpool_buffer_pools_large, GSTATE.masterpool_buffer_pools_small,
                         (0) + GSTATE.ram_profile, bufferpoolGetSmallBufferSize(getWorkerBufferPool(getWID())),
                         bufferpoolGetLargeBufferSize(getWorkerBufferPool(getWID())));

    buffer_pool_t *writer_bpool =
        bufferpoolCreate(GSTATE.masterpool_buffer_pools_large, GSTATE.masterpool_buffer_pools_small,
                         (0) + GSTATE.ram_profile, bufferpoolGetSmallBufferSize(getWorkerBufferPool(getWID())),
                         bufferpoolGetLargeBufferSize(getWorkerBufferPool(getWID())));

    tun_device_t *tdev = memoryAllocate(sizeof(tun_device_t));

    *tdev = (tun_device_t){.name                  = NULL,
                           .running               = false,
                           .up                    = false,
                           .routine_reader        = routineReadFromTun,
                           .routine_writer        = routineWriteToTun,
                           .read_event_callback   = cb,
                           .userdata              = userdata,
                           .writer_buffer_channel = chanOpen(sizeof(void *), kTunWriteChannelQueueMax),
                           .reader_message_pool   = masterpoolCreateWithCapacity(kMasterMessagePoosbufGetLeftCapacity),
                           .reader_buffer_pool    = reader_bpool,
                           .writer_buffer_pool    = writer_bpool,
                           .adapter_handle        = NULL,
                           .session_handle        = NULL,
                           .quit_event            = CreateEventW(NULL, TRUE, FALSE, NULL)};  

    masterpoolInstallCallBacks(tdev->reader_message_pool, allocTunMsgPoolHandle, destroyTunMsgPoolHandle);

    int wideSize = MultiByteToWideChar(CP_UTF8, 0, name, -1, NULL, 0);

    tdev->name = (wchar_t *) malloc(wideSize * sizeof(wchar_t));
    if (! tdev->name )
    {
        LOGE("Memory allocation failed!");
        return NULL;
    }

    MultiByteToWideChar(CP_UTF8, 0, name, -1, (tdev->name), wideSize);

    GUID                  example_guid = {0xdeadbabe, 0xcafe, 0xbeef, {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef}};
    WINTUN_ADAPTER_HANDLE adapter     = WintunCreateAdapter(tdev->name, L"Waterwall Adapter", &example_guid);
    if (! adapter)
    {
        LastError = GetLastError();
        LOGE("Failed to create adapter, code: %lu", LastError);
      
        return NULL;
    }
    tdev->adapter_handle = adapter;

    registerAtExitCallBack(exitHandle, tdev);
    return tdev;
}

/**
 * Destroys the TUN device and releases resources
 * @param tdev TUN device handle
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
        removeAtExitCallBack(exitHandle, tdev);

        WintunCloseAdapter(tdev->adapter_handle);
    }

    CloseHandle(tdev->quit_event);
    memoryFree(tdev->name);
    bufferpoolDestroy(tdev->reader_buffer_pool);
    bufferpoolDestroy(tdev->writer_buffer_pool);
    masterpoolDestroy(tdev->reader_message_pool);
    memoryFree(tdev);
}
