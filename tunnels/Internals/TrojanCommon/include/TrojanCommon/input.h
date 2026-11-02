#pragma once

#include "SocksAddress/address_codec.h"
#include "wwapi.h"

/* Gather a SOCKS address and the requested trailer after a resident prefix.
 * The reader's header storage must fit base + the largest address + trailer.
 * Complete input optionally decodes target; zero ports remain caller policy.
 * Only required header bytes leave their ordinary/splice representation. */
socks_address_result_t trojanGatherAddress(buffer_reader_t *reader, uint16_t base, uint16_t trailer,
                                           socks_address_t *target);

/* Gather and validate a UDP header, including nonzero port and trailing CRLF.
 * The reader retains the header until its body is extracted. body_length is
 * written only on complete valid input; zero-length datagrams are valid. */
socks_address_result_t trojanReadUdpHeader(buffer_reader_t *reader, uint16_t *body_length);
