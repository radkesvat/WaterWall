#pragma once

/* Ordinary UDP length cases shared by the real PTC and CTP ingress fixtures.
 * Each row is sent with both an absent and a nonzero UDP checksum. */
typedef struct udp_length_case_s
{
    uint16_t declared;
    uint16_t available;
    int      delivered;
} udp_length_case_t;

static const udp_length_case_t udp_length_cases[] = {
    {0, 16, -1},
    {7, 16, -1},
    {17, 16, -1},
    {8, 8, 0},
    {8, 16, 0},
    {16, 16, 8},
    {11, 16, 3},
};

enum
{
    kUdpLengthCases       = sizeof(udp_length_cases) / sizeof(udp_length_cases[0]),
    kUdpLengthInputs      = kUdpLengthCases * 2,
    kUdpLengthDeliveries  = 8,
    kUdpLengthFirstPort   = 20000,
    kUdpLengthPayloadSize = 8
};

static const char udp_length_payload[] = "length01";

/* Byte-based checksum oracle, independent of the stack checksum backend. */
static uint16_t udpLengthChecksum(const uint8_t *packet, uint16_t span)
{
    uint32_t sum = 17U + span;
    for (unsigned i = 12; i < 20; i += 2)
        sum += GET_BE16(packet + i);
    for (unsigned i = 0; i + 1 < span; i += 2)
        sum += GET_BE16(packet + 20 + i);
    if ((span & 1U) != 0)
        sum += (uint16_t) packet[20 + span - 1] << 8;
    while ((sum >> 16) != 0)
        sum = (sum & 0xffffU) + (sum >> 16);
    return (uint16_t) ~sum;
}

static void udpLengthSetHeader(uint8_t *packet, unsigned input)
{
    const udp_length_case_t *row = &udp_length_cases[input / 2];
    PUT_BE16(packet + 24, row->declared);
    PUT_BE16(packet + 26, 0);
    if ((input & 1U) != 0)
    {
        if (row->delivered < 0)
            PUT_BE16(packet + 26, 0x1234);
        else
        {
            const uint16_t checksum = udpLengthChecksum(packet, row->declared);
            PUT_BE16(packet + 26, checksum != 0 ? checksum : 0xffff);
            CHECK(udpLengthChecksum(packet, row->declared) == 0);
            if (row->declared < row->available)
                CHECK(udpLengthChecksum(packet, row->available) != 0);
        }
    }
}
