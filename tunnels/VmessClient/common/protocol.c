#include "internal.h"

/* Session material is generated at the first submission, after any transport setup delay. */
bool vmessclientCommitRequest(vmessclient_lstate_t *ls, uint8_t *out, size_t capacity, size_t *written)
{
    vmessclient_tstate_t  *ts      = tunnelGetState(ls->tunnel);
    vmess_request_header_t request = {
        .version  = 1,
        .command  = ls->kind == kVmessClientLineKindUdpCarrier ? 2 : 1,
        .security = ts->security,
        .options  = ts->options,
        .port     = ls->target_addr.port,
    };
    const address_context_t *target = &ls->target_addr;
    if (ts->packetaddr && request.command == 2)
    {
        request.port           = 0;
        request.address_type   = 2;
        request.address_length = sizeof(VMESS_PACKETADDR_DOMAIN) - 1;
        memoryCopy(request.address, VMESS_PACKETADDR_DOMAIN, sizeof(VMESS_PACKETADDR_DOMAIN) - 1);
    }
    else if (addresscontextIsIpv4(target))
    {
        request.address_type   = 1;
        request.address_length = 4;
        memoryCopy(request.address, &target->ip_address.u_addr.ip4.addr, 4);
    }
    else if (addresscontextIsIpv6(target))
    {
        request.address_type   = 3;
        request.address_length = 16;
        memoryCopy(request.address, &target->ip_address.u_addr.ip6, 16);
    }
    else
    {
        request.address_type   = 2;
        request.address_length = target->domain_len;
        memoryCopy(request.address, target->domain, target->domain_len);
    }
    uint8_t auth_id[16], nonce[8], random[4], padding[15];
    getRandomBytes(request.key, sizeof(request.key));
    getRandomBytes(request.iv, sizeof(request.iv));
    getRandomBytes(&request.response, sizeof(request.response));
    getRandomBytes(nonce, sizeof(nonce));
    getRandomBytes(random, sizeof(random));
    getRandomBytes(padding, sizeof(padding));
    size_t padding_length = fastRand32() & 15;
    bool   ok =
        vmessAuthIdCreate(&ts->key, getTimeOfDayMS() / 1000, random, auth_id) == kWCryptoOk &&
        vmessRequestHeaderSeal(
            ts->key.cmd_key, auth_id, nonce, &request, padding, padding_length, out, capacity, written) == kWCryptoOk &&
        vmessResponseKeys(request.key, request.iv, ls->response_key, ls->response_iv) == kWCryptoOk &&
        vmessBodyInit(&ls->output_crypto,
                      request.key,
                      request.iv,
                      request.security,
                      request.options,
                      request.command,
                      true,
                      ts->counter_policy) == kWCryptoOk &&
        vmessBodyInit(&ls->input_crypto,
                      ls->response_key,
                      ls->response_iv,
                      request.security,
                      request.options,
                      request.command,
                      false,
                      ts->counter_policy) == kWCryptoOk;
    if (ok && (request.options & VMESS_OPTION_AUTH_LENGTH))
        ok = vmessBodySetLengthMaterial(&ls->input_crypto, request.key, request.iv) == kWCryptoOk;
    ls->response_marker = request.response;
    memorySecureZero(&request, sizeof(request));
    memorySecureZero(auth_id, sizeof(auth_id));
    memorySecureZero(nonce, sizeof(nonce));
    memorySecureZero(random, sizeof(random));
    memorySecureZero(padding, sizeof(padding));
    if (! ok)
        return false;
    firstPayloadWindowCancel(&ls->first_payload);
    ls->request_sent = true;
    return true;
}
