#include "raw.h"

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
    kMasterMessagePoolsbufGetLeftCapacity = 64,
    kRawWriteChannelQueueMax              = 256
};

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
        LOGE("RawDevice: Failed to get temporary path");
        return NULL;
    }

    // Generate a unique temporary file name
    if (GetTempFileName(tempPath, _T("dll"), 0, tempFileName) == 0)
    {
        LOGE("RawDevice: Failed to create dll filename");
        return NULL;
    }

    // Open the temporary file for writing
    HANDLE hFile = CreateFile(tempFileName, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        LOGE("RawDevice: Failed to create dll file");
        return NULL;
    }

    // Write the DLL bytes to the file
    DWORD bytesWritten;
    if (! WriteFile(hFile, dllBytes, (DWORD) dllSize, &bytesWritten, NULL))
    {
        LOGE("RawDevice: Failed to write dll file");
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
        LOGE("RawDevice: Failed to get temporary path");
        return NULL;
    }

    // Ensure there is a backslash at the end if not already present
    size_t len = _tcslen(tempPath);
    if (tempPath[len - 1] != _T('\\'))
    {
        _tcscat(tempPath, _T("\\"));
    }

    // HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WinDivert
    // Append "mylib.sys"
    _tcscat(tempPath, _T("WinDivert64.sys"));

    // Open the temporary file for writing
    HANDLE hFile = CreateFile(tempPath, GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        // maybe already exsits
        LOGD("RawDevice: the sys file may already exists");
        return _tcsdup(tempFileName);
    }

    // Write the DLL bytes to the file
    DWORD bytesWritten;
    if (! WriteFile(hFile, sysBytes, (DWORD) sysSize, &bytesWritten, NULL))
    {
        LOGE("RawDevice: Failed to write sys file");
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
 * Loads the WinDivert DLL and required functions
 */
static void rawWindowsStartup(void)
{
    if (GSTATE.windivert_dll_handle != NULL)
    {
        LOGD("RawDevice: WinDivert DLL already loaded");
        return;
    }

    // Write the embedded DLL to a temporary file
    TCHAR *tempSysPath = writeSYSToTempFile(&windivert_sys[0], windivert_sys_len);
    if (! tempSysPath)
    {
        LOGE("RawDevice: Failed to write SYS file to temporary file");
        return;
    }

    // Write the embedded DLL to a temporary file
    TCHAR *tempDllPath = writeDllToTempFile(&windivert_dll[0], windivert_dll_len);
    if (! tempDllPath)
    {
        LOGE("RawDevice: Failed to write DLL to temporary file");
        return;
    }

    // Convert TCHAR path to wide string and load the DLL
    WCHAR widePath[MAX_PATH];
    MultiByteToWideChar(CP_ACP, 0, tempDllPath, -1, widePath, MAX_PATH);
    HMODULE hModule = LoadLibraryExW(widePath, NULL, 0);
    if (! hModule)
    {
        LOGE("RawDevice: Failed to load DLL: error %lu", GetLastError());
        DeleteFile(tempDllPath);
        free(tempDllPath);
        return;
    }

    GSTATE.windivert_dll_handle = hModule;
}

static WTHREAD_ROUTINE(routineWriteToRaw) // NOLINT
{
    raw_device_t     *rdev = userdata;
    sbuf_t           *buf;
    WINDIVERT_ADDRESS addr;
    addr.Layer    = WINDIVERT_LAYER_NETWORK; // Set the layer to NETWORK
    addr.Outbound = 1;                       // Set outbound flag to true

    addr.IPChecksum  = 1; // Enable not recalculating IP checksum
    addr.TCPChecksum = 1; // Enable not recalculating TCP checksum
    addr.UDPChecksum = 1; // Enable not recalculating UDP checksum

    while (atomicLoadExplicit(&(rdev->running), memory_order_relaxed))
    {
        if (! chanRecv(rdev->writer_buffer_channel, (void **) &buf))
        {
            LOGD("RawDevice: routine write will exit due to channel closed");
            return 0;
        }

        if (! WinDivertSend(rdev->handle, sbufGetRawPtr(buf), sbufGetLength(buf), NULL, &addr))
        {
            LOGW("RawDevice: WinDivertSend failed: error %lu", GetLastError());
            bufferpoolReuseBuffer(rdev->writer_buffer_pool, buf);
            continue;
        }
        bufferpoolReuseBuffer(rdev->writer_buffer_pool, buf);
    }
    return 0;
}

bool rawdeviceWrite(raw_device_t *rdev, sbuf_t *buf)
{
    assert(sbufGetLength(buf) > sizeof(struct ip_hdr));

    bool closed = false;
    if (! chanTrySend(rdev->writer_buffer_channel, &buf, &closed))
    {
        if (closed)
        {
            LOGE("RawDevice: write failed, channel was closed");
        }
        else
        {
            LOGE("RawDevice: write failed, ring is full");
        }
        return false;
    }
    return true;
}

bool rawdeviceBringUp(raw_device_t *rdev)
{
    assert(! rdev->up);

    bufferpoolUpdateAllocationPaddings(rdev->writer_buffer_pool,
                                       bufferpoolGetLargeBufferPadding(getWorkerBufferPool(getWID())),
                                       bufferpoolGetSmallBufferPadding(getWorkerBufferPool(getWID())));

    rdev->up                    = true;
    rdev->running               = true;
    rdev->writer_buffer_channel = chanOpen(sizeof(void *), kRawWriteChannelQueueMax);

    // rdev->read_thread = threadCreate(rdev->routine_reader, rdev);
    LOGI("RawDevice: device %s is now up", rdev->name);

    rdev->write_thread = threadCreate(rdev->routine_writer, rdev);
    return true;
}

bool rawdeviceBringDown(raw_device_t *rdev)
{
    assert(rdev->up);

    rdev->running = false;
    rdev->up      = false;

    atomicThreadFence(memory_order_release);

    chanClose(rdev->writer_buffer_channel);

    safeThreadJoin(rdev->write_thread);

    sbuf_t *buf;
    while (chanRecv(rdev->writer_buffer_channel, (void **) &buf))
    {
        bufferpoolReuseBuffer(rdev->writer_buffer_pool, buf);
    }

    chanFree(rdev->writer_buffer_channel);
    rdev->writer_buffer_channel = NULL;

    LOGI("RawDevice: device %s is now down", rdev->name);

    return true;
}

// Function to load a function pointer from a DLL
static bool loadFunctionFromDLL(const char *function_name, void *target)
{
    FARPROC proc = GetProcAddress(GSTATE.windivert_dll_handle, function_name);
    if (proc == NULL)
    {
        LOGE("RawDevice: Error: Failed to load function '%s' from WinDivert DLL.", function_name);
        return false;
    }
    memoryCopy(target, &proc, sizeof(FARPROC));
    return true;
}

raw_device_t *rawdeviceCreate(const char *name, uint32_t mark, void *userdata)
{
    if (GSTATE.windivert_dll_handle == NULL)
    {
        rawWindowsStartup();
    }
    if (! loadFunctionFromDLL("WinDivertOpen", &WinDivertOpen))
        return NULL;
    if (! loadFunctionFromDLL("WinDivertSend", &WinDivertSend))
        return NULL;
    if (! loadFunctionFromDLL("WinDivertShutdown", &WinDivertShutdown))
        return NULL;
    if (! loadFunctionFromDLL("WinDivertClose", &WinDivertClose))
        return NULL;

    LOGI("RawDevice: WinDivert loaded successfully");

    HANDLE handle = WinDivertOpen("false", WINDIVERT_LAYER_NETWORK, 0, WINDIVERT_FLAG_SEND_ONLY);
    if (handle == INVALID_HANDLE_VALUE)
    {
        // Handle error
        LOGE("RawDevice: Failed to open WinDivert handle: error %lu", GetLastError());
        return FALSE;
    }

    raw_device_t *rdev = memoryAllocate(sizeof(raw_device_t));

    buffer_pool_t *writer_bpool =
        bufferpoolCreate(GSTATE.masterpool_buffer_pools_large, GSTATE.masterpool_buffer_pools_small, RAM_PROFILE,
                         bufferpoolGetLargeBufferSize(getWorkerBufferPool(getWID())),
                         bufferpoolGetSmallBufferSize(getWorkerBufferPool(getWID()))

        );

    *rdev = (raw_device_t){.name                  = stringDuplicate(name),
                           .running               = false,
                           .up                    = false,
                           .routine_writer        = routineWriteToRaw,
                           .handle                = handle,
                           .mark                  = mark,
                           .userdata              = userdata,
                           .writer_buffer_channel = NULL,
                           .writer_buffer_pool    = writer_bpool};

    return rdev;
}

void rawdeviceDestroy(raw_device_t *rdev)
{

    if (rdev->up)
    {
        rawdeviceBringDown(rdev);
    }
    memoryFree(rdev->name);
    bufferpoolDestroy(rdev->writer_buffer_pool);
    WinDivertShutdown(rdev->handle, WINDIVERT_SHUTDOWN_BOTH);
    WinDivertClose(rdev->handle);
    memoryFree(rdev);
}
