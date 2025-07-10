#include "capture.h"

#include "buffer_pool.h"
#include "global_state.h"
#include "master_pool.h"
#include "wchan.h"
#include "wloop.h"
#include "worker.h"
#include "wplatform.h"
#include <tchar.h>

#include "loggers/internal_logger.h"

// External variables
extern unsigned char windivert_dll[];
extern unsigned int  windivert_dll_len;

extern unsigned char windivert_sys[];
extern unsigned int  windivert_sys_len;

enum
{
    kReadPacketSize                       = 1500,
    kEthDataLen                           = 1500,
    kMasterMessagePoolsbufGetLeftCapacity = 64,
    kQueueLen                             = 512,
    kCaptureWriteChannelQueueMax          = 128
};

struct msg_event
{
    capture_device_t *cdev;
    sbuf_t           *buf;
};

static pool_item_t *allocCaptureMsgPoolHandle(master_pool_t *pool, void *userdata)
{
    discard userdata;
    discard pool;
    return memoryAllocate(sizeof(struct msg_event));
}

static void destroyCaptureMsgPoolHandle(master_pool_t *pool, master_pool_item_t *item, void *userdata)
{
    discard pool;
    discard userdata;
    memoryFree(item);
}

/*
 * WinDivert flags.
 */
#define WINDIVERT_FLAG_SNIFF      0x0001
#define WINDIVERT_FLAG_DROP       0x0002
#define WINDIVERT_FLAG_RECV_ONLY  0x0004
#define WINDIVERT_FLAG_READ_ONLY  WINDIVERT_FLAG_RECV_ONLY
#define WINDIVERT_FLAG_SEND_ONLY  0x0008
#define WINDIVERT_FLAG_WRITE_ONLY WINDIVERT_FLAG_SEND_ONLY
#define WINDIVERT_FLAG_NO_INSTALL 0x0010
#define WINDIVERT_FLAG_FRAGMENTS  0x0020

/*
 * WinDivert layers.
 */
typedef enum
{
    WINDIVERT_LAYER_NETWORK         = 0, /* Network layer. */
    WINDIVERT_LAYER_NETWORK_FORWARD = 1, /* Network layer (forwarded packets) */
    WINDIVERT_LAYER_FLOW            = 2, /* Flow layer. */
    WINDIVERT_LAYER_SOCKET          = 3, /* Socket layer. */
    WINDIVERT_LAYER_REFLECT         = 4, /* Reflect layer. */
} WINDIVERT_LAYER, *PWINDIVERT_LAYER;

/*
 * WinDivert shutdown parameter.
 */
typedef enum
{
    WINDIVERT_SHUTDOWN_RECV = 0x1, /* Shutdown recv. */
    WINDIVERT_SHUTDOWN_SEND = 0x2, /* Shutdown send. */
    WINDIVERT_SHUTDOWN_BOTH = 0x3, /* Shutdown recv and send. */
} WINDIVERT_SHUTDOWN, *PWINDIVERT_SHUTDOWN;

/*
 * WinDivert NETWORK and NETWORK_FORWARD layer data.
 */
typedef struct
{
    UINT32 IfIdx;    /* Packet's interface index. */
    UINT32 SubIfIdx; /* Packet's sub-interface index. */
} WINDIVERT_DATA_NETWORK, *PWINDIVERT_DATA_NETWORK;

/*
 * WinDivert FLOW layer data.
 */
typedef struct
{
    UINT64 EndpointId;       /* Endpoint ID. */
    UINT64 ParentEndpointId; /* Parent endpoint ID. */
    UINT32 ProcessId;        /* Process ID. */
    UINT32 LocalAddr[4];     /* Local address. */
    UINT32 RemoteAddr[4];    /* Remote address. */
    UINT16 LocalPort;        /* Local port. */
    UINT16 RemotePort;       /* Remote port. */
    UINT8  Protocol;         /* Protocol. */
} WINDIVERT_DATA_FLOW, *PWINDIVERT_DATA_FLOW;

/*
 * WinDivert SOCKET layer data.
 */
typedef struct
{
    UINT64 EndpointId;       /* Endpoint ID. */
    UINT64 ParentEndpointId; /* Parent Endpoint ID. */
    UINT32 ProcessId;        /* Process ID. */
    UINT32 LocalAddr[4];     /* Local address. */
    UINT32 RemoteAddr[4];    /* Remote address. */
    UINT16 LocalPort;        /* Local port. */
    UINT16 RemotePort;       /* Remote port. */
    UINT8  Protocol;         /* Protocol. */
} WINDIVERT_DATA_SOCKET, *PWINDIVERT_DATA_SOCKET;

/*
 * WinDivert REFLECTION layer data.
 */
typedef struct
{
    INT64           Timestamp; /* Handle open time. */
    UINT32          ProcessId; /* Handle process ID. */
    WINDIVERT_LAYER Layer;     /* Handle layer. */
    UINT64          Flags;     /* Handle flags. */
    INT16           Priority;  /* Handle priority. */
} WINDIVERT_DATA_REFLECT, *PWINDIVERT_DATA_REFLECT;

/*
 * WinDivert address.
 */
#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable : 4201)
#endif
typedef struct
{
    INT64  Timestamp;       /* Packet's timestamp. */
    UINT32 Layer : 8;       /* Packet's layer. */
    UINT32 Event : 8;       /* Packet event. */
    UINT32 Sniffed : 1;     /* Packet was sniffed? */
    UINT32 Outbound : 1;    /* Packet is outound? */
    UINT32 Loopback : 1;    /* Packet is loopback? */
    UINT32 Impostor : 1;    /* Packet is impostor? */
    UINT32 IPv6 : 1;        /* Packet is IPv6? */
    UINT32 IPChecksum : 1;  /* Packet has valid IPv4 checksum? */
    UINT32 TCPChecksum : 1; /* Packet has valid TCP checksum? */
    UINT32 UDPChecksum : 1; /* Packet has valid UDP checksum? */
    UINT32 Reserved1 : 8;
    UINT32 Reserved2;
    union {
        WINDIVERT_DATA_NETWORK Network; /* Network layer data. */
        WINDIVERT_DATA_FLOW    Flow;    /* Flow layer data. */
        WINDIVERT_DATA_SOCKET  Socket;  /* Socket layer data. */
        WINDIVERT_DATA_REFLECT Reflect; /* Reflect layer data. */
        UINT8                  Reserved3[64];
    };
} WINDIVERT_ADDRESS, *PWINDIVERT_ADDRESS;
#ifdef _MSC_VER
#pragma warning(pop)
#endif

static BOOL (*WinDivertRecv)(HANDLE handle, VOID *pPacket, UINT packetLen, UINT *pRecvLen, WINDIVERT_ADDRESS *pAddr);
static HANDLE (*WinDivertOpen)(const char *filter, WINDIVERT_LAYER layer, INT16 priority, UINT64 flags);
static BOOL (*WinDivertSend)(HANDLE handle, const VOID *pPacket, UINT packetLen, UINT *pSendLen,
                             const WINDIVERT_ADDRESS *pAddr);
static BOOL (*WinDivertShutdown)(HANDLE handle, WINDIVERT_SHUTDOWN how);
static BOOL (*WinDivertClose)(HANDLE handle);

/**
 * Writes the WinDivert DLL bytes to a temporary file on disk
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
        LOGE("CaptureDevice: Failed to get temporary path");
        return NULL;
    }

    // Generate a unique temporary file name
    if (GetTempFileName(tempPath, _T("dll"), 0, tempFileName) == 0)
    {
        LOGE("CaptureDevice: Failed to create dll filename");
        return NULL;
    }

    // Open the temporary file for writing
    HANDLE hFile = CreateFile(tempFileName, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        LOGE("CaptureDevice: Failed to create dll file");
        return NULL;
    }

    // Write the DLL bytes to the file
    DWORD bytesWritten;
    if (! WriteFile(hFile, dllBytes, (DWORD) dllSize, &bytesWritten, NULL))
    {
        LOGE("CaptureDevice: Failed to write dll file");
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
 * Writes the WinDivert SYS bytes to a temporary file on disk
 * @param sysBytes Pointer to the SYS binary data
 * @param sysSize Size of the SYS data in bytes
 * @return Path to the temporary file or NULL on failure
 */
static TCHAR *writeSYSToTempFile(const unsigned char *sysBytes, size_t sysSize)
{
    TCHAR tempPath[MAX_PATH];
    TCHAR tempFileName[MAX_PATH];

    // Get the system's temporary directory
    if (GetTempPath(MAX_PATH, tempPath) == 0)
    {
        LOGE("CaptureDevice: Failed to get temporary path");
        return NULL;
    }

    // Ensure there is a backslash at the end if not already present
    size_t len = _tcslen(tempPath);
    if (tempPath[len - 1] != _T('\\'))
    {
        _tcscat(tempPath, _T("\\"));
    }

    // Append sys file name
    _tcscat(tempPath, _T("WinDivert64.sys"));

    // Open the temporary file for writing
    HANDLE hFile = CreateFile(tempFileName, GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        // maybe already exsits
        LOGD("CaptureDevice: the sys file may already exists");
        return _tcsdup(tempFileName);
    }

    // Write the DLL bytes to the file
    DWORD bytesWritten;
    if (! WriteFile(hFile, sysBytes, (DWORD) sysSize, &bytesWritten, NULL))
    {
        LOGE("CaptureDevice: Failed to write sys file");
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
 * Initializes the Windows RawDevice system
 * Loads the WinDivert DLL and required functions
 */
static void rawWindowsStartup(void)
{
    if (GSTATE.windivert_dll_handle != NULL)
    {
        LOGD("CaptureDevice: WinDivert DLL already loaded");
        return;
    }

    // Write the embedded driver to a temporary file
    TCHAR *tempSysPath = writeSYSToTempFile(&windivert_sys[0], windivert_sys_len);
    if (! tempSysPath)
    {
        LOGE("CaptureDevice: Failed to write SYS file to temporary file");
        return;
    }

    // Write the embedded DLL to a temporary file
    TCHAR *tempDllPath = writeDllToTempFile(&windivert_dll[0], windivert_dll_len);
    if (! tempDllPath)
    {
        LOGE("CaptureDevice: Failed to write DLL to temporary file");
        return;
    }

    // Convert TCHAR path to wide string and load the DLL
    WCHAR widePath[MAX_PATH];
    MultiByteToWideChar(CP_ACP, 0, tempDllPath, -1, widePath, MAX_PATH);
    HMODULE hModule = LoadLibraryExW(widePath, NULL, 0);
    if (! hModule)
    {
        LOGE("CaptureDevice: Failed to load DLL: error %lu", GetLastError());
        DeleteFile(tempDllPath);
        free(tempDllPath);
        return;
    }

    GSTATE.windivert_dll_handle = hModule;
}

static void localThreadEventReceived(wevent_t *ev)
{
    struct msg_event *msg = weventGetUserdata(ev);
    wid_t             tid = (wid_t) (wloopGetWid(weventGetLoop(ev)));


    msg->cdev->read_event_callback(msg->cdev, msg->cdev->userdata, msg->buf, tid);

    masterpoolReuseItems(msg->cdev->reader_message_pool, (void **) &msg, 1, msg->cdev);
}

static void distributePacketPayload(capture_device_t *cdev, wid_t target_wid, sbuf_t *buf)
{

    struct msg_event *msg;
    masterpoolGetItems(cdev->reader_message_pool, (const void **) &(msg), 1, cdev);

    *msg = (struct msg_event){.cdev = cdev, .buf = buf};

    wevent_t ev;
    memorySet(&ev, 0, sizeof(ev));
    ev.loop = getWorkerLoop(target_wid);
    ev.cb   = localThreadEventReceived;
    weventSetUserData(&ev, msg);
    wloopPostEvent(getWorkerLoop(target_wid), &ev);
}
static WTHREAD_ROUTINE(routineReadFromCapture) // NOLINT
{
    capture_device_t *cdev = userdata;
    sbuf_t           *buf;
    UINT              read_packet_len = 0;

    while (atomicLoadExplicit(&(cdev->running), memory_order_relaxed))
    {

        buf = bufferpoolGetSmallBuffer(cdev->reader_buffer_pool);

        buf = sbufReserveSpace(buf, kReadPacketSize);

        if (! WinDivertRecv(cdev->handle, sbufGetMutablePtr(buf), kReadPacketSize, &read_packet_len, NULL))
        {
            LOGE("CaptureDevice: failed to read packet from capture device: error %lu", GetLastError());
            bufferpoolReuseBuffer(cdev->reader_buffer_pool, buf);

            if (ERROR_NO_DATA == GetLastError())
            {
                LOGE("CaptureDevice: Handle shutdown or no data available, exiting read routine...");
                break;
            }
            continue;
        }

        if (UNLIKELY(read_packet_len == 0))
        {
            bufferpoolReuseBuffer(cdev->reader_buffer_pool, buf);
            LOGW("CaptureDevice: read packet with length 0");
            continue;
        }

        sbufSetLength(buf, read_packet_len);

        distributePacketPayload(cdev, getNextDistributionWID(), buf);
    }

    return 0;
}

bool caputredeviceBringUp(capture_device_t *cdev)
{
    assert(! cdev->up);

    cdev->handle =
        WinDivertOpen(cdev->filter, WINDIVERT_LAYER_NETWORK, 0, WINDIVERT_FLAG_RECV_ONLY);
    if (cdev->handle == INVALID_HANDLE_VALUE)
    {
        // Handle error
        LOGE("CaptureDevice: Failed to open WinDivert handle: error %lu", GetLastError());
        return FALSE;
    }

    bufferpoolUpdateAllocationPaddings(cdev->reader_buffer_pool,
                                       bufferpoolGetLargeBufferPadding(getWorkerBufferPool(getWID())),
                                       bufferpoolGetSmallBufferPadding(getWorkerBufferPool(getWID())));

    cdev->up      = true;
    cdev->running = true;

    LOGD("CaptureDevice: device %s is now up", cdev->name);

    cdev->read_thread = threadCreate(cdev->routine_reader, cdev);
    return true;
}

bool caputredeviceBringDown(capture_device_t *cdev)
{
    assert(cdev->up);

    cdev->running = false;
    cdev->up      = false;

    WinDivertShutdown(cdev->handle, WINDIVERT_SHUTDOWN_BOTH);
    WinDivertClose(cdev->handle);

    threadJoin(cdev->read_thread);
    LOGD("CaptureDevice: device %s is now down", cdev->name);

    return true;
}

// Function to load a function pointer from a DLL
static bool loadFunctionFromDLL(const char *function_name, void *target)
{
    FARPROC proc = GetProcAddress(GSTATE.windivert_dll_handle, function_name);
    if (proc == NULL)
    {
        LOGE("CaptureDevice: Error: Failed to load function '%s' from WinDivert DLL.", function_name);
        return false;
    }
    memoryCopy(target, &proc, sizeof(FARPROC));
    return true;
}
capture_device_t *caputredeviceCreate(const char *name, const char *capture_ip, void *userdata,
                                      CaptureReadEventHandle cb)
{

    if (GSTATE.windivert_dll_handle == NULL)
    {
        rawWindowsStartup();
    }
    if (! loadFunctionFromDLL("WinDivertOpen", &WinDivertOpen))
        return NULL;
    if (! loadFunctionFromDLL("WinDivertRecv", &WinDivertRecv))
        return NULL;
    if (! loadFunctionFromDLL("WinDivertSend", &WinDivertSend))
        return NULL;
    if (! loadFunctionFromDLL("WinDivertShutdown", &WinDivertShutdown))
        return NULL;
    if (! loadFunctionFromDLL("WinDivertClose", &WinDivertClose))
        return NULL;

    buffer_pool_t *reader_bpool =
        bufferpoolCreate(GSTATE.masterpool_buffer_pools_large, GSTATE.masterpool_buffer_pools_small, RAM_PROFILE,
                         bufferpoolGetLargeBufferSize(getWorkerBufferPool(getWID())),
                         bufferpoolGetSmallBufferSize(getWorkerBufferPool(getWID()))

        );

    capture_device_t *cdev = memoryAllocate(sizeof(capture_device_t));

    *cdev =
        (capture_device_t){.name                = stringDuplicate(name),
                           .running             = false,
                           .up                  = false,
                           .routine_reader      = routineReadFromCapture,
                           .handle              = NULL,
                           .read_event_callback = cb,
                           .userdata            = userdata,
                           .reader_message_pool = masterpoolCreateWithCapacity(kMasterMessagePoolsbufGetLeftCapacity),
                           .reader_buffer_pool  = reader_bpool};

    memorySet(cdev->filter, 0, sizeof(cdev->filter));
    stringNPrintf(cdev->filter, sizeof(cdev->filter), "ip.SrcAddr == %s", capture_ip);

    masterpoolInstallCallBacks(cdev->reader_message_pool, allocCaptureMsgPoolHandle, destroyCaptureMsgPoolHandle);

    return cdev;
}

void capturedeviceDestroy(capture_device_t *cdev)
{
    if (cdev->up)
    {
        caputredeviceBringDown(cdev);
    }
    memoryFree(cdev->name);
    bufferpoolDestroy(cdev->reader_buffer_pool);
    masterpoolMakeEmpty(cdev->reader_message_pool, NULL);
    masterpoolDestroy(cdev->reader_message_pool);

    WinDivertShutdown(cdev->handle, WINDIVERT_SHUTDOWN_BOTH);
    WinDivertClose(cdev->handle);
    memoryFree(cdev);
}
