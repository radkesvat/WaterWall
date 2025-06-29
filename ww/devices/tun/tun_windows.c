#include "tun.h"

#include "buffer_pool.h"
#include "global_state.h"
#include "managers/signal_manager.h"
#include "master_pool.h"
#include "wchan.h"
#include "wintun/wintun.h"
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
    if (! WriteFile(hFile, dllBytes, (DWORD) dllSize, &bytesWritten, NULL))
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

    LOGI("TunDevice: DLL loaded successfully");

    GSTATE.wintun_dll_handle = hModule;
}

/**
 * Event message structure for TUN device communication
 */
struct msg_event
{
    tun_device_t *tdev;
    sbuf_t       *bufs[kMaxReadQueueSize];
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
    wloopPostEvent(getWorkerLoop(target_wid), &ev);
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
    tun_device_t         *tdev          = userdata;
    WINTUN_SESSION_HANDLE Session       = tdev->session_handle;
    HANDLE                WaitHandles[] = {WintunGetReadWaitEvent(Session), tdev->quit_event};
    sbuf_t               *buf[kMaxReadQueueSize];
    uint8_t               queued_count = 0;
    ssize_t               nread;

    while (atomicLoadRelaxed(&(tdev->running)))
    {
        buf[queued_count] = bufferpoolGetSmallBuffer(tdev->reader_buffer_pool);
        assert(sbufGetRightCapacity(buf[queued_count]) >= kReadPacketSize);

        DWORD packet_size;
        BYTE *packet = WintunReceivePacket(Session, &packet_size);
        if (packet)
        {
            sbufSetLength(buf[queued_count], packet_size);
            memoryCopyLarge(sbufGetMutablePtr(buf[queued_count]), packet, packet_size);

            WintunReleaseReceivePacket(Session, packet);

            if (TUN_LOG_EVERYTHING)
            {
                LOGD("TunDevice: ReadThread: Read %zd bytes from device %s", nread, tdev->name);
                // printPacket(Packet, PacketSize);
            }

            if (queued_count < kMaxReadQueueSize - 1)
            {
                queued_count++;
            }
            else
            {
                distributePacketPayloads(tdev, getNextDistributionWID(), &buf[0], queued_count);

                queued_count = 0;
            }
        }
        else
        {

            bufferpoolReuseBuffer(tdev->reader_buffer_pool, buf[queued_count]);

            DWORD last_error = GetLastError();
            switch (last_error)
            {
            // case ERROR_NO_MORE_ITEMS:
            case ERROR_NO_MORE_ITEMS:
                if (queued_count > 0)
                {
                    distributePacketPayloads(tdev, getNextDistributionWID(), &buf[0], queued_count);

                    queued_count = 0;
                    continue;
                }
                if (WaitForMultipleObjects(_countof(WaitHandles), WaitHandles, FALSE, INFINITE) == WAIT_OBJECT_0)
                {
                    continue;
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
        if (!chanRecv(tdev->writer_buffer_channel, (void**)&buf))
        {
            LOGD("TunDevice: WriteThread: Terminating due to closed channel");
            return 0;
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

/**
 * Brings the TUN device up and starts the read/write threads
 * @param tdev TUN device handle
 * @return true if successful, false otherwise
 */
bool tundeviceBringUp(tun_device_t *tdev)
{
    if (tdev->up)
    {
        LOGE("TunDevice: Device is already up");
        return false;
    }

    tdev->writer_buffer_channel = chanOpen(sizeof(void*),kTunWriteChannelQueueMax);
    MemoryBarrier();

    LOGD("TunDevice: Starting WinTun session");
    WINTUN_SESSION_HANDLE Session = WintunStartSession(tdev->adapter_handle, 0x400000);
    if (! Session)
    {
        DWORD lastError = GetLastError();
        LOGE("TunDevice: Failed to start session, code: %lu", lastError);
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
        LOGE("TunDevice: Device is already down");
        return true;
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
    LOGD("TunDevice: Ending WinTun session");
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
        LOGE("TunDevice: Cannot set IP -> Invalid IP address: %s", ip_presentation);
    }

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
    AddressRow->Address.Ipv4.sin_family           = AF_INET;
    AddressRow->Address.Ipv4.sin_addr.S_un.S_addr = ip_binary;
    AddressRow->OnLinkPrefixLength                = (uint8_t) subnet;
    AddressRow->DadState                          = IpDadStatePreferred;
    DWORD LastError                               = CreateUnicastIpAddressEntry(AddressRow);
    if (LastError != ERROR_SUCCESS && LastError != ERROR_OBJECT_ALREADY_EXISTS)
    {
        LOGE("TunDevice: Failed to set IP address, code: %lu", LastError);
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
    discard subnet;
    discard ip_presentation;

    if (tdev->adapter_handle == NULL)
    {
        LOGE("TunDevice: Cannot set IP -> No Adapter!");
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
        LOGE("TunDevice: Failed to unassign IP address, code: %lu", LastError);
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
    assert(sbufGetLength(buf) > 20);
    if (atomicLoadRelaxed(&(tdev->running)) == false)
    {
        LOGE("TunDevice: Write failed, device is not running");
        return false;
    }

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

    LOGD("TunDevice: Wintun loaded successfully");

    buffer_pool_t *reader_bpool =
        bufferpoolCreate(GSTATE.masterpool_buffer_pools_large, GSTATE.masterpool_buffer_pools_small, RAM_PROFILE,

                         bufferpoolGetLargeBufferSize(getWorkerBufferPool(getWID())),
                         bufferpoolGetSmallBufferSize(getWorkerBufferPool(getWID()))

        );

    buffer_pool_t *writer_bpool =
        bufferpoolCreate(GSTATE.masterpool_buffer_pools_large, GSTATE.masterpool_buffer_pools_small, RAM_PROFILE,

                         bufferpoolGetLargeBufferSize(getWorkerBufferPool(getWID())),
                         bufferpoolGetSmallBufferSize(getWorkerBufferPool(getWID()))

        );

    bufferpoolUpdateAllocationPaddings(reader_bpool, bufferpoolGetLargeBufferPadding(getWorkerBufferPool(getWID())),
                                       bufferpoolGetSmallBufferPadding(getWorkerBufferPool(getWID())));

    bufferpoolUpdateAllocationPaddings(writer_bpool, bufferpoolGetLargeBufferPadding(getWorkerBufferPool(getWID())),
                                       bufferpoolGetSmallBufferPadding(getWorkerBufferPool(getWID())));

    tun_device_t *tdev = memoryAllocate(sizeof(tun_device_t));

    *tdev = (tun_device_t) {.name                  = NULL,
                            .running               = false,
                            .up                    = false,
                            .routine_reader        = routineReadFromTun,
                            .routine_writer        = routineWriteToTun,
                            .read_event_callback   = cb,
                            .userdata              = userdata,
                            .writer_buffer_channel = chanOpen(sizeof(void*),kTunWriteChannelQueueMax),
                            .reader_message_pool   = masterpoolCreateWithCapacity(kMasterMessagePoolsbufGetLeftCapacity),
                            .reader_buffer_pool    = reader_bpool,
                            .writer_buffer_pool    = writer_bpool,
                            .adapter_handle        = NULL,
                            .session_handle        = NULL,
                            .quit_event            = CreateEventW(NULL, TRUE, FALSE, NULL)};

    masterpoolInstallCallBacks(tdev->reader_message_pool, allocTunMsgPoolHandle, destroyTunMsgPoolHandle);

    int wideSize = MultiByteToWideChar(CP_UTF8, 0, name, -1, NULL, 0);

    tdev->name = (wchar_t *) malloc(wideSize * sizeof(wchar_t));
    if (! tdev->name)
    {
        LOGE("TunDevice: Memory allocation failed!");
        return NULL;
    }

    MultiByteToWideChar(CP_UTF8, 0, name, -1, (tdev->name), wideSize);

    GUID example_guid = {0xDEADC0DE, 0xFADE, 0xC01D, {0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66}};

    LOGD("TunDevice: Creating adapter with GUID: %08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x", example_guid.Data1,
         example_guid.Data2, example_guid.Data3, example_guid.Data4[0], example_guid.Data4[1], example_guid.Data4[2],
         example_guid.Data4[3], example_guid.Data4[4], example_guid.Data4[5], example_guid.Data4[6],
         example_guid.Data4[7]);

    WINTUN_ADAPTER_HANDLE adapter = WintunCreateAdapter(tdev->name, L"Waterwall Adapter", &example_guid);
    if (! adapter)
    {
        LastError = GetLastError();
        LOGE("TunDevice: Failed to create adapter! code: %lu", LastError);

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

    CloseHandle(tdev->quit_event);
    memoryFree(tdev->name);
    bufferpoolDestroy(tdev->reader_buffer_pool);
    bufferpoolDestroy(tdev->writer_buffer_pool);
    masterpoolDestroy(tdev->reader_message_pool);
    chanFree(tdev->writer_buffer_channel);

    memoryFree(tdev);
}
