/*
 * Covers: packet tunnel; the explicit inputs, callbacks and expected results below define this suite.
 * Setup: Real runtime/component code with the explicit worker/line/neighbour fixture and any linker
 * seams shown below. Line and buffer settlement remains the scenario owner's responsibility.
 * Cases: testPacketTunnelLifecycleCallbacksPassThrough, testFragmentPolicySettings
 * Checks: Assertion labels include: packet tunnel did not forward upstream Init to next; packet tunnel did
 * not forward upstream Est to next; packet tunnel did not forward upstream Pause to next; packet tunnel
 * did not forward upstream Resume to next
 * Limits: Platform/feature branches remain conditional. Component fixtures do not establish host-network
 * or application-throughput behavior.
 * CTest: waterwall.packet_tunnel_unit
 */
#include "wwapi.h"

#include "test_assert.h"

#define require(condition, message) TEST_REQUIRE(TEST_FAILURE_EXIT, condition, message)

typedef enum callback_kind_e
{
    kCallbackNone,
    kCallbackInit,
    kCallbackEst,
    kCallbackFinish,
    kCallbackPause,
    kCallbackResume,
} callback_kind_t;

typedef void (*lifecycle_callback_t)(tunnel_t *, line_t *);

static callback_kind_t observed_kind;
static tunnel_t       *observed_tunnel;
static line_t         *observed_line;


static void recordCallback(tunnel_t *t, line_t *l, callback_kind_t kind)
{
    observed_kind   = kind;
    observed_tunnel = t;
    observed_line   = l;
}

static void recordInit(tunnel_t *t, line_t *l)
{
    recordCallback(t, l, kCallbackInit);
}

static void recordEst(tunnel_t *t, line_t *l)
{
    recordCallback(t, l, kCallbackEst);
}

static void recordFinish(tunnel_t *t, line_t *l)
{
    recordCallback(t, l, kCallbackFinish);
}

static void recordPause(tunnel_t *t, line_t *l)
{
    recordCallback(t, l, kCallbackPause);
}

static void recordResume(tunnel_t *t, line_t *l)
{
    recordCallback(t, l, kCallbackResume);
}

static void installRecorders(tunnel_t *t)
{
    t->fnInitU   = recordInit;
    t->fnInitD   = recordInit;
    t->fnEstU    = recordEst;
    t->fnEstD    = recordEst;
    t->fnFinU    = recordFinish;
    t->fnFinD    = recordFinish;
    t->fnPauseU  = recordPause;
    t->fnPauseD  = recordPause;
    t->fnResumeU = recordResume;
    t->fnResumeD = recordResume;
}

static void requireForwarded(lifecycle_callback_t callback, tunnel_t *packet_tunnel, tunnel_t *expected_tunnel,
                             callback_kind_t expected_kind, const char *message)
{
    line_t line = {.active_tunnels_mask = UINT64_MAX};

    observed_kind   = kCallbackNone;
    observed_tunnel = NULL;
    observed_line   = NULL;

    callback(packet_tunnel, &line);

    require(observed_kind == expected_kind, message);
    require(observed_tunnel == expected_tunnel, message);
    require(observed_line == &line, message);
}

static void testPacketTunnelLifecycleCallbacksPassThrough(void)
{
    tunnel_t *prev          = tunnelCreate(NULL, 0, 0);
    tunnel_t *packet_tunnel = packettunnelCreate(NULL, 0, 0);
    tunnel_t *next          = tunnelCreate(NULL, 0, 0);

    require(prev != NULL && packet_tunnel != NULL && next != NULL, "failed to create lifecycle test tunnels");

    tunnelBind(prev, packet_tunnel);
    tunnelBind(packet_tunnel, next);
    installRecorders(prev);
    installRecorders(next);

    requireForwarded(packet_tunnel->fnInitU,
                     packet_tunnel,
                     next,
                     kCallbackInit,
                     "packet tunnel did not forward upstream Init to next");
    requireForwarded(
        packet_tunnel->fnEstU, packet_tunnel, next, kCallbackEst, "packet tunnel did not forward upstream Est to next");
    requireForwarded(packet_tunnel->fnPauseU,
                     packet_tunnel,
                     next,
                     kCallbackPause,
                     "packet tunnel did not forward upstream Pause to next");
    requireForwarded(packet_tunnel->fnResumeU,
                     packet_tunnel,
                     next,
                     kCallbackResume,
                     "packet tunnel did not forward upstream Resume to next");
    requireForwarded(packet_tunnel->fnFinU,
                     packet_tunnel,
                     next,
                     kCallbackFinish,
                     "packet tunnel did not forward upstream Finish to next");

    requireForwarded(packet_tunnel->fnInitD,
                     packet_tunnel,
                     prev,
                     kCallbackInit,
                     "packet tunnel did not forward downstream Init to prev");
    requireForwarded(packet_tunnel->fnEstD,
                     packet_tunnel,
                     prev,
                     kCallbackEst,
                     "packet tunnel did not forward downstream Est to prev");
    requireForwarded(packet_tunnel->fnPauseD,
                     packet_tunnel,
                     prev,
                     kCallbackPause,
                     "packet tunnel did not forward downstream Pause to prev");
    requireForwarded(packet_tunnel->fnResumeD,
                     packet_tunnel,
                     prev,
                     kCallbackResume,
                     "packet tunnel did not forward downstream Resume to prev");
    requireForwarded(packet_tunnel->fnFinD,
                     packet_tunnel,
                     prev,
                     kCallbackFinish,
                     "packet tunnel did not forward downstream Finish to prev");

    require(packet_tunnel->fnPayloadU != tunnelDefaultUpStreamPayload,
            "packet tunnel unexpectedly inherited the upstream payload pass-through");
    require(packet_tunnel->fnPayloadD != tunnelDefaultDownStreamPayload,
            "packet tunnel unexpectedly inherited the downstream payload pass-through");

    tunnelDestroy(next);
    tunnelDestroy(packet_tunnel);
    tunnelDestroy(prev);
}

static void testFragmentPolicySettings(void)
{
    static const struct
    {
        const char              *json;
        device_fragment_policy_t expected;
    } cases[] = {
        {"{}", kDeviceFragmentReassemble},
        {"{\"fragment-policy\":\"reassemble\"}", kDeviceFragmentReassemble},
        {"{\"fragment-policy\":\"preserve-fragments\"}", kDeviceFragmentPreserve},
        {"{\"fragment-policy\":null}", kDeviceFragmentPolicyUnset},
        {"{\"fragment-policy\":false}", kDeviceFragmentPolicyUnset},
        {"{\"fragment-policy\":0}", kDeviceFragmentPolicyUnset},
        {"{\"fragment-policy\":[]}", kDeviceFragmentPolicyUnset},
        {"{\"fragment-policy\":{}}", kDeviceFragmentPolicyUnset},
        {"{\"fragment-policy\":\"\"}", kDeviceFragmentPolicyUnset},
        {"{\"fragment-policy\":\"invalid\"}", kDeviceFragmentPolicyUnset},
    };

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i)
    {
        cJSON *settings = cJSON_Parse(cases[i].json);
        require(settings != NULL, "failed to parse fragment policy settings");
        device_fragment_policy_t policy   = kDeviceFragmentPolicyUnset;
        const bool               accepted = packettunnelReadFragmentPolicy(settings, &policy);
        require(accepted == (cases[i].expected != kDeviceFragmentPolicyUnset),
                "fragment policy setting was incorrectly accepted or rejected");
        if (accepted)
        {
            require(policy == cases[i].expected, "fragment policy default or explicit value was not retained");
        }
        cJSON_Delete(settings);
    }
}

static bool checksumValid(const uint8_t *bytes, uint32_t length)
{
    uint32_t sum = 0;
    for (uint32_t i = 0; i < length; i += 2)
        sum += ((uint32_t) bytes[i] << 8) | (i + 1 < length ? bytes[i + 1] : 0);
    while (sum >> 16)
        sum = (sum & UINT32_C(0xffff)) + (sum >> 16);
    return sum == UINT32_C(0xffff);
}

static sbuf_t *makeChecksumPacket(void)
{
    sbuf_t *buf = sbufCreate(28);
    sbufSetLength(buf, 28);
    uint8_t *bytes = sbufGetMutablePtr(buf);
    memoryZero(bytes, 28);
    bytes[0]  = 0x45;
    bytes[8]  = 64;
    bytes[9]  = 1;
    bytes[20] = 8;
    bytes[27] = 1;
    PUT_BE16(bytes + 2, 28);
    PUT_BE32(bytes + 12, UINT32_C(0xc0000201));
    PUT_BE32(bytes + 16, UINT32_C(0xc6336401));
    return buf;
}

static void testBufferChecksumRequests(void)
{
    sbuf_t *marked   = makeChecksumPacket();
    sbuf_t *unmarked = sbufDuplicate(marked);
    uint8_t original[28];
    memoryCopy(original, sbufGetRawPtr(unmarked), sizeof(original));
    sbufSetRecalculateChecksum(marked, true);
    require(packettunnelConsumeChecksumRequest(marked), "marked ICMP packet was refused");
    require(! sbufGetRecalculateChecksum(marked), "successful repair left a request");
    const uint8_t *repaired = sbufGetRawPtr(marked);
    require(checksumValid(repaired, 20) && checksumValid(repaired + 20, 8),
            "repair did not produce valid IPv4 and ICMP checksums");
    require(packettunnelConsumeChecksumRequest(unmarked), "structurally valid unmarked packet was refused");
    require(memcmp(original, sbufGetRawPtr(unmarked), sizeof(original)) == 0,
            "unrequested checksum corruption was changed");

    for (unsigned invalid = 0; invalid < 6; ++invalid)
    {
        for (unsigned requested = 0; requested < 2; ++requested)
        {
            sbuf_t  *bad   = makeChecksumPacket();
            uint8_t *bytes = sbufGetMutablePtr(bad);
            switch (invalid)
            {
            case 0:
                sbufSetLength(bad, 19);
                break;
            case 1:
                bytes[0] = 0x65;
                break;
            case 2:
                bytes[0] = 0x44;
                break;
            case 3:
                PUT_BE16(bytes + 2, 27);
                break;
            case 4:
                PUT_BE16(bytes + 2, 29);
                break;
            case 5:
                bytes[0] = 0x4f;
                break;
            }
            sbufSetRecalculateChecksum(bad, requested != 0);
            require(! packettunnelConsumeChecksumRequest(bad), "malformed packet passed checksum boundary");
            require(! sbufGetRecalculateChecksum(bad), "terminal refusal retained a request");
            sbufDestroy(bad);
            require(! sbufGetRecalculateChecksum(unmarked), "dropped packet changed another packet's request");
        }
    }
    sbufSetRecalculateChecksum(marked, true);
    require(packettunnelTakeChecksumRequest(marked) && ! packettunnelTakeChecksumRequest(marked),
            "taking a request did not clear exactly that buffer");
    sbufDestroy(unmarked);
    sbufDestroy(marked);
}

int main(void)
{
    testCaseSet("packet_tunnel_test");
    testPacketTunnelLifecycleCallbacksPassThrough();
    testFragmentPolicySettings();
    testBufferChecksumRequests();
    return 0;
}
