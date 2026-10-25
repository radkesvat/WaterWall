/*
 * Covers: bounded VMess request/response/body and packetaddr parser mutation.
 * Setup: independent vectors, no sockets; deterministic finite corpus mutations
 * run in native Debug/Release and the existing ASan/UBSan unit preset.
 * Cases: every partial prefix, malformed lengths, unsupported addresses, split
 * and coalesced records, EOF/tag corruption, and seeded wrap boundary ordinals.
 * CTest: waterwall.vmess_parser_fuzz_unit.
 * LLVMFuzzerTestOneInput is also usable with a sanitizer fuzzer driver by
 * defining VMESS_LIBFUZZER. Generated corpora/results belong under build/.
 */
#include "wwapi.h"

#include "VmessCommon/crypto.h"
#include "test_assert.h"
#include "vectors.h"

#define require(condition, message) TEST_REQUIRE(TEST_FAILURE_EXIT, condition, message)

enum
{
    kMutationInputMax = 4096
};

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t length);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t length)
{
    if (length < 1 || length > kMutationInputMax)
    {
        return 0;
    }
    uint8_t operation = *data++ % 5;
    --length;
    if (operation == 0)
    {
        vmess_request_header_t header;
        wcrypto_status_t       status = vmessRequestHeaderParse(data, length, &header);
        if (status == kWCryptoOk)
        {
            require(vmessModeValid(header.security, header.options, header.command),
                    "fuzz accepted invalid request mode");
            require(header.port != 0 || vmessRequestIsPacketAddr(&header), "fuzz accepted ordinary zero port");
            require(header.address_type != 2 || ! vmessIsPacketAddrDomain(header.address, header.address_length) ||
                        vmessRequestIsPacketAddr(&header),
                    "fuzz accepted reserved domain as ordinary target");
        }
        wCryptoZero(&header, sizeof(header));
    }
    else if (operation == 1)
    {
        if (length >= VMESS_REQUEST_PREFIX_SIZE)
        {
            uint16_t         plain_length = 0;
            wcrypto_status_t status = vmessRequestLengthOpen(vector_cmd, data, data + 16, data + 34, &plain_length);
            if (status == kWCryptoOk && length - VMESS_REQUEST_PREFIX_SIZE >= (size_t) plain_length + 16)
            {
                vmess_request_header_t header;
                status = vmessRequestHeaderOpen(
                    vector_cmd, data, data + 34, data + VMESS_REQUEST_PREFIX_SIZE, (size_t) plain_length + 16, &header);
                if (status == kWCryptoOk)
                {
                    require(header.port != 0 || vmessRequestIsPacketAddr(&header), "fuzz sealed ordinary zero port");
                    require(header.address_type != 2 ||
                                ! vmessIsPacketAddrDomain(header.address, header.address_length) ||
                                vmessRequestIsPacketAddr(&header),
                            "fuzz opened reserved domain as ordinary target");
                }
                wCryptoZero(&header, sizeof(header));
            }
        }
    }
    else if (operation == 2)
    {
        if (length >= 18)
        {
            uint16_t         plain_length = 0;
            wcrypto_status_t status =
                vmessResponseLengthOpen(vector_response_key, vector_response_iv, data, &plain_length);
            if (status == kWCryptoOk && length - 18 >= (size_t) plain_length + 16)
            {
                status = vmessResponseHeaderOpen(
                    vector_response_key, vector_response_iv, 61, data + 18, (size_t) plain_length + 16);
            }
            (void) status;
        }
    }
    else if (operation == 3)
    {
        vmess_packet_addr_t address;
        size_t              header_length = 0;
        wcrypto_status_t    status        = vmessPacketAddrDecode(data, length, &address, &header_length);
        if (status == kWCryptoOk)
        {
            require(header_length <= length && header_length == vmessPacketAddrHeaderSize(&address) &&
                        address.port != 0,
                    "fuzz accepted invalid packetaddr envelope");
        }
        else
        {
            require(header_length == 0, "fuzz exposed partial packetaddr envelope");
        }
    }
    else if (length != 0)
    {
        uint8_t control = *data++;
        --length;
        const uint8_t    profiles[] = {1, 5, 13, 17, 21, 29};
        uint8_t          options    = profiles[(control & 7U) % sizeof(profiles)];
        uint8_t          security   = (control & 128U) != 0 ? VMESS_SECURITY_NONE
                                      : (control & 8U) != 0 ? VMESS_SECURITY_CHACHA20_POLY1305
                                                            : VMESS_SECURITY_AES128_GCM;
        const uint8_t   *key        = (control & 32U) != 0 ? vector_response_key : vector_key;
        const uint8_t   *iv         = (control & 32U) != 0 ? vector_response_iv : vector_iv;
        vmess_body_ctx_t ctx        = {0};
        wcrypto_status_t status     = vmessBodyInit(
            &ctx, key, iv, security, options, 2, false, (control & 64U) != 0 ? kVmessCounterStrict : kVmessCounterWrap);
        if (status == kWCryptoOk && (control & 32U) != 0 && (options & VMESS_OPTION_AUTH_LENGTH) != 0)
        {
            status = vmessBodySetLengthMaterial(&ctx, vector_key, vector_iv);
        }
        ctx.counter = (control & 16U) != 0 ? UINT16_MAX : 0;
        for (unsigned records = 0; status == kWCryptoOk && length != 0 && records < 8; ++records)
        {
            size_t   prefix      = vmessBodyLengthSize(&ctx);
            uint32_t body_length = 0;
            status               = vmessBodyLengthOpen(&ctx, data, length < prefix ? length : prefix, &body_length);
            if (status != kWCryptoOk || length < prefix || body_length > length - prefix)
            {
                break;
            }
            uint8_t output[kMutationInputMax];
            size_t  plain_length = 0;
            bool    eof          = false;
            status = vmessBodyOpen(&ctx, data + prefix, body_length, output, sizeof(output), &plain_length, &eof);
            if (status != kWCryptoOk)
            {
                require(plain_length == 0 && ! eof && ctx.failed, "fuzz exposed unauthenticated body result");
                break;
            }
            require(plain_length <= body_length && eof == ctx.ended, "fuzz decoded invalid body bounds");
            if (! eof)
            {
                vmess_packet_addr_t address;
                size_t              header_length = 0;
                wcrypto_status_t    envelope = vmessPacketAddrDecode(output, plain_length, &address, &header_length);
                (void) envelope;
            }
            wCryptoZero(output, sizeof(output));
            data += prefix + body_length;
            length -= prefix + body_length;
            if (eof)
            {
                break;
            }
        }
        vmessBodyDestroy(&ctx);
    }
    return 0;
}

#ifndef VMESS_LIBFUZZER
static void mutate(uint8_t operation, uint8_t control, const uint8_t *seed, size_t seed_length)
{
    uint8_t corpus[kMutationInputMax];
    size_t  offset = operation == 4 ? 2 : 1;
    require(seed_length + offset + 1 <= sizeof(corpus), "fuzz seed exceeds finite input bound");
    corpus[0] = operation;
    if (operation == 4)
    {
        corpus[1] = control;
    }
    memcpy(corpus + offset, seed, seed_length);
    size_t length = offset + seed_length;
    LLVMFuzzerTestOneInput(corpus, length);
    for (size_t partial = 0; partial < length; ++partial)
    {
        LLVMFuzzerTestOneInput(corpus, partial);
    }
    for (size_t index = 0; index < length; ++index)
    {
        uint8_t saved = corpus[index];
        for (unsigned bit = 0; bit < 8; ++bit)
        {
            corpus[index] = saved ^ (uint8_t) (1U << bit);
            LLVMFuzzerTestOneInput(corpus, length);
        }
        corpus[index] = saved;
    }
    corpus[length] = 0;
    LLVMFuzzerTestOneInput(corpus, length + 1);
    corpus[length] = UINT8_MAX;
    LLVMFuzzerTestOneInput(corpus, length + 1);
}

int main(void)
{
    testCaseSet("vmess_parser_fuzz_test");
    require(wCryptoGlobalInit() == kWCryptoOk, "fuzz crypto initialization failed");
    mutate(0, 0, vector_plain_header, sizeof(vector_plain_header));
    mutate(0, 0, vector_plain_header_udp, sizeof(vector_plain_header_udp));
    mutate(1, 0, vector_request, sizeof(vector_request));
    mutate(1, 0, vector_request_udp, sizeof(vector_request_udp));
    mutate(1, 0, vector_request_domain_max, sizeof(vector_request_domain_max));
    mutate(1, 0, vector_request_packetaddr, sizeof(vector_request_packetaddr));
    mutate(1, 0, vector_request_packetaddr_udp_wrong_port, sizeof(vector_request_packetaddr_udp_wrong_port));
    mutate(1, 0, vector_request_packetaddr_tcp_wrong_port, sizeof(vector_request_packetaddr_tcp_wrong_port));
    mutate(1, 0, vector_request_packetaddr_tcp_zero_port, sizeof(vector_request_packetaddr_tcp_zero_port));
    mutate(1, 0, vector_request_zero_port, sizeof(vector_request_zero_port));
    mutate(2, 0, vector_response, sizeof(vector_response));
    mutate(2, 0, vector_response_command_max, sizeof(vector_response_command_max));
    mutate(2, 0, vector_response_short_command, sizeof(vector_response_short_command));
    mutate(2, 0, vector_response_too_large, sizeof(vector_response_too_large));
    mutate(3, 0, vector_packetaddr_v4, sizeof(vector_packetaddr_v4));
    mutate(3, 0, vector_packetaddr_v6, sizeof(vector_packetaddr_v6));
    const uint8_t profiles[] = {1, 5, 13, 17, 21, 29};
    for (size_t first = 0; first < sizeof(vector_frames) / sizeof(vector_frames[0]); first += 3)
    {
        const vmess_vector_t *frame   = &vector_frames[first];
        uint8_t               control = frame->security == VMESS_SECURITY_NONE                ? 128
                                        : frame->security == VMESS_SECURITY_CHACHA20_POLY1305 ? 8
                                                                                              : 0;
        for (uint8_t index = 0; index < sizeof(profiles); ++index)
        {
            if (profiles[index] == frame->options)
            {
                control |= index;
                break;
            }
        }
        uint8_t coalesced[512];
        size_t  length = 0;
        for (unsigned index = 0; index < 3; ++index)
        {
            frame = &vector_frames[first + index];
            memcpy(coalesced + length, frame->wire, frame->length);
            length += frame->length;
        }
        mutate(4, control, coalesced, length);
    }
    mutate(4, 16, vector_last_counter, sizeof(vector_last_counter));
    mutate(4, 16 | 5, vector_last_counter_auth_aes, sizeof(vector_last_counter_auth_aes));
    mutate(4, 16 | 8 | 5, vector_last_counter_auth_chacha, sizeof(vector_last_counter_auth_chacha));
    uint8_t  state[kMutationInputMax];
    uint32_t random = UINT32_C(0x81253213);
    for (unsigned round = 0; round < 2048; ++round)
    {
        size_t length = round % sizeof(state) + 1;
        for (size_t index = 0; index < length; ++index)
        {
            random ^= random << 13;
            random ^= random >> 17;
            random ^= random << 5;
            state[index] = (uint8_t) random;
        }
        LLVMFuzzerTestOneInput(state, length);
    }
    wCryptoGlobalCleanup();
    return 0;
}
#endif
