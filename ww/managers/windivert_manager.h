#pragma once

#include "wlibc.h"

/*
 * WinDivert manager
 * -----------------
 * Centralizes loading of the embedded WinDivert driver (.sys) and user-mode
 * library (.dll), resolving the exported functions once, and exposing thin
 * wrappers so that every part of the program that needs WinDivert (the Capture
 * device, the TUN loop-guard, ...) shares a single loaded instance instead of
 * each subsystem re-implementing driver extraction and DLL loading.
 *
 * Everything here is Windows-only. On other platforms the header is empty so it
 * can still be included unconditionally.
 */

#ifdef OS_WIN

#include <windows.h>

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
 * WinDivert event.
 */
typedef enum
{
    WINDIVERT_EVENT_NETWORK_PACKET   = 0, /* Network packet. */
    WINDIVERT_EVENT_FLOW_ESTABLISHED = 1, /* Flow established. */
    WINDIVERT_EVENT_FLOW_DELETED     = 2, /* Flow deleted. */
    WINDIVERT_EVENT_SOCKET_BIND      = 3, /* Socket bind. */
    WINDIVERT_EVENT_SOCKET_CONNECT   = 4, /* Socket connect. */
    WINDIVERT_EVENT_SOCKET_LISTEN    = 5, /* Socket listen. */
    WINDIVERT_EVENT_SOCKET_ACCEPT    = 6, /* Socket accept. */
    WINDIVERT_EVENT_SOCKET_CLOSE     = 7, /* Socket close. */
    WINDIVERT_EVENT_REFLECT_OPEN     = 8, /* WinDivert handle opened. */
    WINDIVERT_EVENT_REFLECT_CLOSE    = 9, /* WinDivert handle closed. */
} WINDIVERT_EVENT, *PWINDIVERT_EVENT;

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

/**
 * @brief Ensure the embedded WinDivert driver + DLL are loaded and the API is
 *        resolved.
 *
 * Idempotent: the driver/DLL are extracted and loaded only on the first
 * successful call, the resolved function pointers are cached afterwards. Intended
 * to be called from the (single-threaded) startup path of any subsystem that
 * needs WinDivert.
 *
 * @return true when the WinDivert API is ready to use through the wrappers below.
 */
bool windivertManagerEnsureLoaded(void);

/* Thin wrappers over the dynamically resolved WinDivert exports. They must only
 * be used after windivertManagerEnsureLoaded() has returned true. */
HANDLE windivertOpen(const char *filter, WINDIVERT_LAYER layer, INT16 priority, UINT64 flags);
BOOL   windivertRecv(HANDLE handle, void *packet, UINT packet_len, UINT *recv_len, WINDIVERT_ADDRESS *addr);
BOOL   windivertSend(HANDLE handle, const void *packet, UINT packet_len, UINT *send_len, const WINDIVERT_ADDRESS *addr);
BOOL   windivertShutdown(HANDLE handle, WINDIVERT_SHUTDOWN how);
BOOL   windivertClose(HANDLE handle);

/* Address-format helpers (host byte order input for the IPv4 variant, UINT[4]
 * array for the IPv6 variant), used to safely decode SOCKET/FLOW layer
 * addresses without hand-rolling WinDivert's internal byte layout. */
BOOL windivertHelperFormatIPv4Address(UINT32 addr, char *buffer, UINT buffer_len);
BOOL windivertHelperFormatIPv6Address(const UINT32 *addr, char *buffer, UINT buffer_len);

#endif // OS_WIN
