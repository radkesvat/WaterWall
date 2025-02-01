#include "wintun.h"
#include "wplatform.h"
#include <ip2string.h>
#include <iphlpapi.h>
#include <mstcpip.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <winsock2.h>
#include <winternl.h>
#include <ws2ipdef.h>

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

static HMODULE InitializeWintun(void)
{
    HMODULE Wintun =
        LoadLibraryExW(L"wintun.dll", NULL, LOAD_LIBRARY_SEARCH_APPLICATION_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (! Wintun)
        return NULL;
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
        return NULL;
    }
    return Wintun;
}

static void CALLBACK ConsoleLogger(_In_ WINTUN_LOGGER_LEVEL Level, _In_ DWORD64 Timestamp, _In_z_ const WCHAR *LogLine)
{
    SYSTEMTIME SystemTime;
    FileTimeToSystemTime((FILETIME *) &Timestamp, &SystemTime);
    WCHAR LevelMarker;
    switch (Level)
    {
    case WINTUN_LOG_INFO:
        LevelMarker = L'+';
        break;
    case WINTUN_LOG_WARN:
        LevelMarker = L'-';
        break;
    case WINTUN_LOG_ERR:
        LevelMarker = L'!';
        break;
    default:
        return;
    }
    fwprintf(stderr, L"%04u-%02u-%02u %02u:%02u:%02u.%04u [%c] %s\n", SystemTime.wYear, SystemTime.wMonth,
             SystemTime.wDay, SystemTime.wHour, SystemTime.wMinute, SystemTime.wSecond, SystemTime.wMilliseconds,
             LevelMarker, LogLine);
}

static DWORD64 Now(VOID)
{
    LARGE_INTEGER Timestamp;
    NtQuerySystemTime(&Timestamp);
    return Timestamp.QuadPart;
}

static DWORD LogError(_In_z_ const WCHAR *Prefix, _In_ DWORD Error)
{
    WCHAR *SystemMessage = NULL, *FormattedMessage = NULL;
    FormatMessageW(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_MAX_WIDTH_MASK, NULL,
                   HRESULT_FROM_SETUPAPI(Error), MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (void *) &SystemMessage, 0,
                   NULL);
    FormatMessageW(FORMAT_MESSAGE_FROM_STRING | FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_ARGUMENT_ARRAY |
                       FORMAT_MESSAGE_MAX_WIDTH_MASK,
                   SystemMessage ? L"%1: %3(Code 0x%2!08X!)" : L"%1: Code 0x%2!08X!", 0, 0, (void *) &FormattedMessage,
                   0, (va_list *) (DWORD_PTR[]) {(DWORD_PTR) Prefix, (DWORD_PTR) Error, (DWORD_PTR) SystemMessage});
    if (FormattedMessage)
        ConsoleLogger(WINTUN_LOG_ERR, Now(), FormattedMessage);
    LocalFree(FormattedMessage);
    LocalFree(SystemMessage);
    return Error;
}

static DWORD LogLastError(_In_z_ const WCHAR *Prefix)
{
    DWORD LastError = GetLastError();
    LogError(Prefix, LastError);
    SetLastError(LastError);
    return LastError;
}

static void Log(_In_ WINTUN_LOGGER_LEVEL Level, _In_z_ const WCHAR *Format, ...)
{
    WCHAR   LogLine[0x200];
    va_list args;
    va_start(args, Format);
    _vsnwprintf_s(LogLine, _countof(LogLine), _TRUNCATE, Format, args);
    va_end(args);
    ConsoleLogger(Level, Now(), LogLine);
}

static HANDLE        QuitEvent;
static volatile BOOL HaveQuit;

static BOOL WINAPI CtrlHandler(_In_ DWORD CtrlType)
{
    switch (CtrlType)
    {
    case CTRL_C_EVENT:
    case CTRL_BREAK_EVENT:
    case CTRL_CLOSE_EVENT:
    case CTRL_LOGOFF_EVENT:
    case CTRL_SHUTDOWN_EVENT:
        Log(WINTUN_LOG_INFO, L"Cleaning up and shutting down...");
        HaveQuit = TRUE;
        SetEvent(QuitEvent);
        return TRUE;
    }
    return FALSE;
}

static void PrintPacket(_In_ const BYTE *Packet, _In_ DWORD PacketSize)
{
    if (PacketSize < 20)
    {
        Log(WINTUN_LOG_INFO, L"Received packet without room for an IP header");
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
        Log(WINTUN_LOG_INFO, L"Received packet without room for an IP header");
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
        Log(WINTUN_LOG_INFO, L"Received packet that was not IP");
        return;
    }
    if (Proto == 1 && PacketSize >= 8 && Packet[0] == 0)
        Log(WINTUN_LOG_INFO, L"Received IPv%d ICMP echo reply from %s to %s", IpVersion, Src, Dst);
    else
        Log(WINTUN_LOG_INFO, L"Received IPv%d proto 0x%x packet from %s to %s", IpVersion, Proto, Src, Dst);
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

static void MakeICMP(_Out_writes_bytes_all_(28) BYTE Packet[28])
{
    memorySet(Packet, 0, 28);
    Packet[0]               = 0x45;
    *(USHORT *) &Packet[2]  = htons(28);
    Packet[8]               = 255;
    Packet[9]               = 1;
    *(ULONG *) &Packet[12]  = htonl((10 << 24) | (6 << 16) | (7 << 8) | (8 << 0)); /* 10.6.7.8 */
    *(ULONG *) &Packet[16]  = htonl((10 << 24) | (6 << 16) | (7 << 8) | (7 << 0)); /* 10.6.7.7 */
    *(USHORT *) &Packet[10] = IPChecksum(Packet, 20);
    Packet[20]              = 8;
    *(USHORT *) &Packet[22] = IPChecksum(&Packet[20], 8);
    Log(WINTUN_LOG_INFO, L"Sending IPv4 ICMP echo request to 10.6.7.8 from 10.6.7.7");
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
                LogError(L"Packet read failed", LastError);
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

int __cdecl main(void)
{
    HMODULE Wintun = InitializeWintun();
    if (! Wintun)
        return LogError(L"Failed to initialize Wintun", GetLastError());
    WintunSetLogger(ConsoleLogger);
    Log(WINTUN_LOG_INFO, L"Wintun library loaded");

    DWORD LastError;
    HaveQuit  = FALSE;
    QuitEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (! QuitEvent)
    {
        LastError = LogError(L"Failed to create event", GetLastError());
        goto cleanupWintun;
    }
    if (! SetConsoleCtrlHandler(CtrlHandler, TRUE))
    {
        LastError = LogError(L"Failed to set console handler", GetLastError());
        goto cleanupQuit;
    }

    GUID                  ExampleGuid = {0xdeadbabe, 0xcafe, 0xbeef, {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef}};
    WINTUN_ADAPTER_HANDLE Adapter     = WintunCreateAdapter(L"Demo", L"Example", &ExampleGuid);
    if (! Adapter)
    {
        LastError = GetLastError();
        LogError(L"Failed to create adapter", LastError);
        goto cleanupQuit;
    }

    DWORD Version = WintunGetRunningDriverVersion();
    Log(WINTUN_LOG_INFO, L"Wintun v%u.%u loaded", (Version >> 16) & 0xff, (Version >> 0) & 0xff);

    MIB_UNICASTIPADDRESS_ROW AddressRow;
    InitializeUnicastIpAddressEntry(&AddressRow);
    WintunGetAdapterLUID(Adapter, &AddressRow.InterfaceLuid);
    AddressRow.Address.Ipv4.sin_family           = AF_INET;
    AddressRow.Address.Ipv4.sin_addr.S_un.S_addr = htonl((10 << 24) | (6 << 16) | (7 << 8) | (7 << 0)); /* 10.6.7.7 */
    AddressRow.OnLinkPrefixLength                = 24; /* This is a /24 network */
    AddressRow.DadState                          = IpDadStatePreferred;
    LastError                                    = CreateUnicastIpAddressEntry(&AddressRow);
    if (LastError != ERROR_SUCCESS && LastError != ERROR_OBJECT_ALREADY_EXISTS)
    {
        LogError(L"Failed to set IP address", LastError);
        goto cleanupAdapter;
    }

    WINTUN_SESSION_HANDLE Session = WintunStartSession(Adapter, 0x400000);
    if (! Session)
    {
        LastError = LogLastError(L"Failed to create adapter");
        goto cleanupAdapter;
    }

    Log(WINTUN_LOG_INFO, L"Launching threads and mangling packets...");

    HANDLE Workers[] = {CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE) ReceivePackets, (LPVOID) Session, 0, NULL),
                        CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE) SendPackets, (LPVOID) Session, 0, NULL)};
    if (! Workers[0] || ! Workers[1])
    {
        LastError = LogError(L"Failed to create threads", GetLastError());
        goto cleanupWorkers;
    }
    WaitForMultipleObjectsEx(_countof(Workers), Workers, TRUE, INFINITE, TRUE);
    LastError = ERROR_SUCCESS;

cleanupWorkers:
    HaveQuit = TRUE;
    SetEvent(QuitEvent);
    for (size_t i = 0; i < _countof(Workers); ++i)
    {
        if (Workers[i])
        {
            WaitForSingleObject(Workers[i], INFINITE);
            CloseHandle(Workers[i]);
        }
    }
    WintunEndSession(Session);
cleanupAdapter:
    WintunCloseAdapter(Adapter);
cleanupQuit:
    SetConsoleCtrlHandler(CtrlHandler, FALSE);
    CloseHandle(QuitEvent);
cleanupWintun:
    FreeLibrary(Wintun);
    return LastError;
}
