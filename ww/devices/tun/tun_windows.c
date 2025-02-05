#include "global_state.h"
#include "wlibc.h"
#include <ip2string.h>
#include <tchar.h>

#include "loggers/internal_logger.h"

#include "wintun/wintun.h"

extern unsigned char wintun_dll;
extern unsigned int  wintun_dll_len;

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

// Function to write the embedded DLL to a temporary file
TCHAR *writeDllToTempFile(const unsigned char *dllBytes, size_t dllSize)
{
    TCHAR tempPath[MAX_PATH];
    TCHAR tempFileName[MAX_PATH];

    // Get the system's temporary directory
    if (GetTempPath(MAX_PATH, tempPath) == 0)
    {
        LOGE("Failed to get temporary path.");
        return NULL;
    }

    // Generate a unique temporary file name
    if (GetTempFileName(tempPath, _T("dll"), 0, tempFileName) == 0)
    {
        LOGE("Failed to create temporary file name.");
        return NULL;
    }

    // Open the temporary file for writing
    HANDLE hFile = CreateFile(tempFileName, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        LOGE("Failed to create temporary file.");
        return NULL;
    }

    // Write the DLL bytes to the file
    DWORD bytesWritten;
    if (! WriteFile(hFile, dllBytes, (DWORD) dllSize, &bytesWritten, NULL))
    {
        LOGE("Failed to write to temporary file.");
        CloseHandle(hFile);
        DeleteFile(tempFileName);
        return NULL;
    }

    // Close the file handle
    CloseHandle(hFile);

    // Return the path to the temporary file
    return _tcsdup(tempFileName);
}

static void tunWindowsStartup(void)
{
    // Write the embedded DLL to a temporary file
    TCHAR *tempDllPath = WriteDllToTempFile(wintun_dll, wintun_dll_len);
    if (! tempDllPath)
    {
        LOGE("Failed to write DLL to temporary file.");
        return 1;
    }

    // Load the DLL using LoadLibraryExW
    HMODULE hModule = LoadLibraryExW(tempDllPath, NULL, 0);

    if (! hModule)
    {
        LOGE("Failed to load DLL: %lu", GetLastError());
        DeleteFile(tempDllPath);
        free(tempDllPath);
        return 1;
    }

    LOGI("DLL loaded successfully.");

    // Optionally, call functions from the DLL
    FARPROC func = GetProcAddress(hModule, "SomeFunction");
    if (func)
    {
        LOGI("Function 'SomeFunction' found.");
        // Call the function here
    }
    else
    {
        LOGW("Failed to find function: %lu", GetLastError());
    }

    // Clean up
    FreeLibrary(hModule);
    DeleteFile(tempDllPath);
    free(tempDllPath);
}

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
        LOGI("Received IPv%d ICMP echo reply from %s to %s", IpVersion, Src, Dst);
    else
        LOGI("Received IPv%d proto 0x%x packet from %s to %s", IpVersion, Proto, Src, Dst);
}

static USHORT IPChecksum(_In_reads_bytes_(Len) BYTE *Buffer, _In_ DWORD Len)
{
    ULONG Sum = 0;
    for (; Len > 1; Len -= 2, Buffer += 2)
        Sum += *(USHORT *) Buffer;
    if (Len)
        Sum += *Buffer;
    Sum = (Sum >> 16) + (Sum & 0xffff);
    Sum += (Sum >> 16);
    return (USHORT) (~Sum);
}



// Handle local thread event
static void localThreadEventReceived(wevent_t *ev) {
    struct msg_event *msg = weventGetUserdata(ev);
    wid_t             tid = (wid_t) (wloopTID(weventGetLoop(ev)));

    msg->tdev->read_event_callback(msg->tdev, msg->tdev->userdata, msg->buf, tid);
    masterpoolReuseItems(msg->tdev->reader_message_pool, (void **) &msg, 1, msg->tdev);
}

// Distribute packet payload to the target thread
static void distributePacketPayload(tun_device_t *tdev, wid_t target_tid, sbuf_t *buf) {
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

// Routine to read from TUN device
static WTHREAD_ROUTINE(routineReadFromTun) {
    tun_device_t *tdev           = userdata;
    wid_t         distribute_tid = 0;
    sbuf_t       *buf;
    ssize_t       nread;

    WINTUN_SESSION_HANDLE Session       = (WINTUN_SESSION_HANDLE) SessionPtr;
    HANDLE                WaitHandles[] = {WintunGetReadWaitEvent(Session), QuitEvent};


    while (atomicLoadExplicit(&(tdev->running), memory_order_relaxed)) {
        buf = bufferpoolGetSmallBuffer(tdev->reader_buffer_pool);
        assert(sbufGetRightCapacity(buf) >= kReadPacketSize);

        nread = read(tdev->handle, sbufGetMutablePtr(buf), kReadPacketSize);

        if (nread == 0) {
            bufferpoolReuseBuffer(tdev->reader_buffer_pool, buf);
            LOGW("TunDevice: Exit read routine due to End Of File");
            return 0;
        }

        if (nread < 0) {
            bufferpoolReuseBuffer(tdev->reader_buffer_pool, buf);
            LOGE("TunDevice: reading a packet from TUN device failed, code: %d", (int) nread);
            if (errno == EINVAL || errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
                continue;
            }
            LOGE("TunDevice: Exit read routine due to critical error");
            return 0;
        }

        sbufSetLength(buf, nread);

        if (TUN_LOG_EVERYTHING) {
            LOGD("TunDevice: read %zd bytes from device %s", nread, tdev->name);
        }

        distributePacketPayload(tdev, distribute_tid++, buf);

        if (distribute_tid >= getWorkersCount()) {
            distribute_tid = 0;
        }
    }

    return 0;
}

static DWORD WINAPI ReceivePackets(_Inout_ DWORD_PTR SessionPtr)
{
    WINTUN_SESSION_HANDLE Session       = (WINTUN_SESSION_HANDLE) SessionPtr;
    HANDLE                WaitHandles[] = {WintunGetReadWaitEvent(Session), QuitEvent};

    while (! HaveQuit)
    {
        DWORD PacketSize;
        BYTE *Packet = WintunReceivePacket(Session, &PacketSize);
        if (Packet)
        {
            PrintPacket(Packet, PacketSize);
            WintunReleaseReceivePacket(Session, Packet);
        }
        else
        {
            DWORD LastError = GetLastError();
            switch (LastError)
            {
            case ERROR_NO_MORE_ITEMS:
                if (WaitForMultipleObjects(_countof(WaitHandles), WaitHandles, FALSE, INFINITE) == WAIT_OBJECT_0)
                    continue;
                return ERROR_SUCCESS;
            default:
                LOGE("Packet read failed: %lu", LastError);
                return LastError;
            }
        }
    }
    return ERROR_SUCCESS;
}

static DWORD WINAPI SendPackets(_Inout_ DWORD_PTR SessionPtr)
{
    WINTUN_SESSION_HANDLE Session = (WINTUN_SESSION_HANDLE) SessionPtr;
    while (! HaveQuit)
    {
        BYTE *Packet = WintunAllocateSendPacket(Session, 28);
        if (Packet)
        {
            MakeICMP(Packet);
            WintunSendPacket(Session, Packet);
        }
        else if (GetLastError() != ERROR_BUFFER_OVERFLOW)
            return LogLastError(L"Packet write failed");

        switch (WaitForSingleObject(QuitEvent, 1000 /* 1 second */))
        {
        case WAIT_ABANDONED:
        case WAIT_OBJECT_0:
            return ERROR_SUCCESS;
        }
    }
    return ERROR_SUCCESS;
}




// Routine to write to TUN device
static WTHREAD_ROUTINE(routineWriteToTun) {
    tun_device_t *tdev = userdata;
    sbuf_t       *buf;
    ssize_t       nwrite;

    while (atomicLoadExplicit(&(tdev->running), memory_order_relaxed)) {
        if (! chanRecv(tdev->writer_buffer_channel, (void*) &buf)) {
            LOGD("TunDevice: routine write will exit due to channel closed");
            return 0;
        }

        assert(sbufGetBufLength(buf) > sizeof(struct iphdr));

        nwrite = write(tdev->handle, sbufGetRawPtr(buf), sbufGetBufLength(buf));
        bufferpoolReuseBuffer(tdev->writer_buffer_pool, buf);

        if (nwrite == 0) {
            LOGW("TunDevice: Exit write routine due to End Of File");
            return 0;
        }

        if (nwrite < 0) {
            LOGW("TunDevice: writing a packet to TUN device failed, code: %d", (int) nwrite);
            if (errno == EINVAL || errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
                continue;
            }
            LOGE("TunDevice: Exit write routine due to critical error");
            return 0;
        }
    }
    return 0;
}













// Function prototypes
tun_device_t *tundeviceCreate(const char *name, bool offload, void *userdata, TunReadEventHandle cb)
{
    if (! GSTATE.internal_flag_tundev_windows_initialized)
    {
        tunWindowsStartup();
        GSTATE.internal_flag_tundev_windows_initialized = true;
    }

    if (GSTATE.wintun_dll_handle == NULL)
    {
        LOGE("TunDevice: Wintun DLL not loaded");
        return NULL;
    }

#define X(Name) ((*(FARPROC *) &Name = GetProcAddress(Wintun, #Name)) == NULL)
    if (X(WintunCreateAdapter) || X(WintunCloseAdapter) || X(WintunOpenAdapter) || X(WintunGetAdapterLUID) ||
        X(WintunGetRunningDriverVersion) || X(WintunDeleteDriver) || X(WintunSetLogger) || X(WintunStartSession) ||
        X(WintunEndSession) || X(WintunGetReadWaitEvent) || X(WintunReceivePacket) || X(WintunReleaseReceivePacket) ||
        X(WintunAllocateSendPacket) || X(WintunSendPacket))
#undef X
    {
        DWORD LastError = GetLastError();
        FreeLibrary(Wintun);
        SetLastError(LastError);
        LOGE("TunDevice: Could not setup Wintun functions, Code: %lu", LastError);

        return NULL;
    }
}

bool tundeviceBringUp(tun_device_t *tdev);
bool tundeviceBringDown(tun_device_t *tdev);
bool tundeviceAssignIP(tun_device_t *tdev, const char *ip_presentation, unsigned int subnet);
bool tundeviceUnAssignIP(tun_device_t *tdev, const char *ip_presentation, unsigned int subnet);
bool tundeviceWrite(tun_device_t *tdev, sbuf_t *buf);
