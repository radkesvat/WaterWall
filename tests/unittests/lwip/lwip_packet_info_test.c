/*
 * Covers: bounded packet debug formatting and captured logging as data.
 * Setup: read-only packet bytes ending at an inaccessible page, real logger.
 * Checks: empty/truncated/unknown/unaligned headers, exact bounded byte dump,
 * normal IPv4/IPv6 addresses, long prefixes and literal formatting directives.
 * CTest: waterwall.lwip_packet_info_unit
 */
#include "loggers/internal_logger.h"
#include "loggers/network_logger.h"
#include "test_assert.h"
#include "ww_lwip.h"

#include <sys/mman.h>
#include <unistd.h>

#define require(condition, message) TEST_REQUIRE(TEST_FAILURE_EXIT, condition, message)

static char     capture[512];
static size_t   captured;
static unsigned calls;

static void captureLog(int level, const char *bytes, int length)
{
    require(level == LOG_LEVEL_DEBUG && length > 0 && length <= 256, "packet log exceeded its bounded message");
    require(bytes[length - 1] == '\n', "logger lost its message terminator");
    memcpy(capture, bytes, (size_t) length);
    capture[length] = '\0';
    captured        = (size_t) length;
    ++calls;
}

static logger_t *createCaptureLogger(void)
{
    logger_t *logger = loggerCreate();
    require(logger != NULL, "capture logger creation failed");
    loggerSetHandler(logger, captureLog);
    loggerSetLevel(logger, LOG_LEVEL_DEBUG);
    loggerSetFormat(logger, "%s");
    return logger;
}

static void checkPacket(size_t length, uint8_t version, uint8_t ihl, const char *expected)
{
    const long page_result = sysconf(_SC_PAGESIZE);
    require(page_result > 0, "page-size query failed");
    const size_t page    = (size_t) page_result;
    uint8_t     *mapping = mmap(NULL, page * 2, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    require(mapping != MAP_FAILED, "guarded packet allocation failed");
    require(mprotect(mapping + page, page, PROT_NONE) == 0, "packet guard protection failed");
    uint8_t *packet = mapping + page - length;
    for (size_t i = 0; i < length; ++i)
        packet[i] = (uint8_t) i;
    if (length != 0)
        packet[0] = (uint8_t) ((version << 4) | ihl);
    if (version == 4 && length >= 20)
    {
        packet[9] = IP_PROTO_UDP;
        PUT_BE32(packet + 12, UINT32_C(0x0a000001));
        PUT_BE32(packet + 16, UINT32_C(0xc0000201));
    }
    if (version == 6 && length >= 40)
    {
        packet[6] = IP_PROTO_TCP;
        memset(packet + 8, 0, 32);
        packet[23] = 1;
        packet[39] = 2;
    }
    require(mprotect(mapping, page, PROT_READ) == 0, "packet read-only protection failed");
    calls = 0;
    printIPPacketInfo("packet %s%n", packet, length);
    require(calls == 1 && captured == strlen(capture), "packet log was missing or unterminated");
    require(strstr(capture, "packet %s%n : ") == capture, "packet prefix was treated as a format");
    require(strstr(capture, expected) != NULL, "packet header classification/address changed");
    const char *dump = strstr(capture, "Data: ");
    require(dump != NULL, "packet byte dump is missing");
    dump += strlen("Data: ");
    const size_t dumped = min(length, (size_t) 16);
    for (size_t i = 0; i < dumped; ++i)
    {
        char byte[4];
        require(snprintf(byte, sizeof(byte), "%02x ", packet[i]) == 3, "byte oracle formatting failed");
        require(memcmp(dump + i * 3, byte, 3) == 0, "packet dump changed available bytes");
    }
    require(strcmp(dump + dumped * 3, "\n") == 0, "packet dumped unavailable bytes or more than sixteen");
    require(munmap(mapping, page * 2) == 0, "guarded packet release failed");
}

int main(void)
{
    testCaseSet("length-aware bounded packet formatter");
    /* The production PCH can select InternalLogger before ww_lwip.c includes
     * NetworkLogger. Capture either established compilation configuration. */
    setInternalLogger(createCaptureLogger());
    setNetworkLogger(createCaptureLogger());

    calls = 0;
    printIPPacketInfo("empty", NULL, 0);
    require(calls == 1 && strstr(capture, "Empty packet, Data: \n") != NULL, "null empty input was not logged");
    checkPacket(0, 4, 5, "Empty packet");
    for (size_t length = 1; length < 20; ++length)
        checkPacket(length, 4, 5, "Truncated IPv4 header");
    checkPacket(1, 7, 0, "Unknown IP version");
    checkPacket(20, 4, 0, "Invalid IPv4 header");
    checkPacket(20, 4, 6, "Truncated IPv4 header");
    checkPacket(20, 4, 5, "From 10.0.0.1 to 192.0.2.1");
    checkPacket(21, 4, 5, "From 10.0.0.1 to 192.0.2.1");
    checkPacket(24, 4, 6, "From 10.0.0.1 to 192.0.2.1");
    for (size_t length = 1; length < 40; ++length)
        checkPacket(length, 6, 0, "Truncated IPv6 header");
    checkPacket(40, 6, 0, "From ::1 to ::2");
    checkPacket(41, 6, 0, "From ::1 to ::2");

    char prefix[8192];
    memset(prefix, 'P', sizeof(prefix) - 1);
    memcpy(prefix, "%s%n%p", 6);
    prefix[sizeof(prefix) - 1] = '\0';
    const uint8_t unknown      = 0x70;
    calls                      = 0;
    printIPPacketInfo(prefix, &unknown, 1);
    require(calls == 1 && captured == 256 && memcmp(capture, prefix, 255) == 0 && capture[255] == '\n',
            "long prefix escaped output bounds or was treated as a format");

    networkloggerDestroy();
    internaloggerDestroy();
    puts("bounded packet header formatting and logging passed");
    return 0;
}
