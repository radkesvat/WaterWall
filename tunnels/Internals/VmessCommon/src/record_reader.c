#include "VmessCommon/record_reader.h"

void vmessRecordReaderInit(vmess_record_reader_t *reader, buffer_pool_t *pool, buffer_budget_t *budget)
{
    assert(reader != NULL && pool != NULL && budget != NULL);
    *reader = (vmess_record_reader_t) {.pool = pool, .budget = budget};
}

static sbuf_t *recordInputHead(vmess_record_reader_t *reader, const vmess_record_input_t *input)
{
    while (true)
    {
        if (*input->head == NULL)
            *input->head = bufferqueuePopFrontReserved(input->pending, input->reservation);
        sbuf_t *head = *input->head;
        if (head == NULL)
            return NULL;
        assert(! sbufIsSplice(head));
        assert(input->reservation->budget == reader->budget);
        assert(input->reservation->cost.bytes == sbufGetLength(head));
        if (sbufGetLength(head) != 0)
            return head;
        bufferbudgetReservationRelease(input->reservation);
        bufferpoolReuseBuffer(reader->pool, head);
        *input->head = NULL;
    }
}

/* Transfer already-admitted bytes without releasing or reacquiring total usage.
 * The prefix_filled/body reservation fields become their new accounting owner. */
static uint32_t recordGather(vmess_record_reader_t *reader, const vmess_record_input_t *input, uint8_t *destination,
                             uint32_t needed)
{
    uint32_t gathered = 0;
    while (gathered < needed)
    {
        sbuf_t *head = recordInputHead(reader, input);
        if (head == NULL)
            break;
        uint32_t count = min(needed - gathered, sbufGetLength(head));
        sbufReadRangeToMemory(head, destination + gathered, count);
        input->reservation->cost.bytes -= count;
        gathered += count;
        if (sbufGetLength(head) == 0)
        {
            bufferbudgetReservationRelease(input->reservation);
            bufferpoolReuseBuffer(reader->pool, head);
            *input->head = NULL;
        }
    }
    return gathered;
}

vmess_record_result_t vmessRecordReaderRead(vmess_record_reader_t *reader, vmess_body_ctx_t *crypto,
                                            const vmess_record_input_t *input)
{
    assert(reader != NULL && reader->pool != NULL && reader->budget != NULL);
    assert(crypto != NULL && ! crypto->raw && ! crypto->encrypt && ! crypto->failed && ! crypto->ended);
    assert(input != NULL && input->pending != NULL && input->head != NULL && input->reservation != NULL);
    assert(input->pending->budget == reader->budget);
    assert((*input->head == NULL && input->reservation->budget == NULL) ||
           (*input->head != NULL && input->reservation->budget == reader->budget));
    assert((reader->body != NULL) == crypto->pending);

    vmess_record_result_t result = {.status = kVmessRecordNeedMore};
    if (! crypto->pending)
    {
        uint32_t prefix_length = (uint32_t) vmessBodyLengthSize(crypto);
        assert(prefix_length <= sizeof(reader->prefix) && reader->prefix_filled <= prefix_length);
        uint32_t gathered =
            recordGather(reader, input, reader->prefix + reader->prefix_filled, prefix_length - reader->prefix_filled);
        reader->prefix_filled += (uint16_t) gathered;
        result.consumed += gathered;
        if (reader->prefix_filled < prefix_length)
            return result;
        if (vmessBodyLengthOpen(crypto, reader->prefix, prefix_length, &reader->body_length) != kWCryptoOk)
        {
            result.status = kVmessRecordLengthError;
            return result;
        }
        bufferbudgetRelease(reader->budget, (buffer_budget_cost_t) {.bytes = reader->prefix_filled});
        reader->prefix_filled = 0;
        reader->body =
            bufferpoolGetBestFit(reader->pool, reader->body_length, bufferpoolGetLargeBufferPadding(reader->pool));
        sbufSetLength(reader->body, 0);
        if (! bufferbudgetTryReserve(reader->budget, reader->body, &reader->body_reservation))
        {
            result.status = kVmessRecordLimitError;
            return result;
        }
    }

    uint32_t gathered = recordGather(reader,
                                     input,
                                     sbufGetMutablePtr(reader->body) + reader->body_filled,
                                     reader->body_length - reader->body_filled);
    reader->body_filled += gathered;
    reader->body_reservation.cost.bytes += gathered;
    result.consumed += gathered;
    if (reader->body_filled < reader->body_length)
        return result;

    size_t           plaintext_length = 0;
    bool             eof              = false;
    wcrypto_status_t status           = vmessBodyOpen(crypto,
                                            sbufGetRawPtr(reader->body),
                                            reader->body_length,
                                            sbufGetMutablePtr(reader->body),
                                            reader->body_length,
                                            &plaintext_length,
                                            &eof);
    bufferbudgetReservationRelease(&reader->body_reservation);
    sbuf_t *body        = reader->body;
    reader->body        = NULL;
    reader->body_length = reader->body_filled = 0;
    if (status != kWCryptoOk || eof)
    {
        bufferpoolReuseBuffer(reader->pool, body);
        result.status = status != kWCryptoOk ? kVmessRecordBodyError : kVmessRecordEof;
        return result;
    }
    sbufSetLength(body, plaintext_length);
    result.status  = kVmessRecordPayload;
    result.payload = body;
    return result;
}

void vmessRecordReaderDestroy(vmess_record_reader_t *reader)
{
    assert(reader != NULL);
    if (reader->prefix_filled != 0)
        bufferbudgetRelease(reader->budget, (buffer_budget_cost_t) {.bytes = reader->prefix_filled});
    bufferbudgetReservationRelease(&reader->body_reservation);
    if (reader->body != NULL)
        bufferpoolReuseBuffer(reader->pool, reader->body);
    *reader = (vmess_record_reader_t) {0};
}
