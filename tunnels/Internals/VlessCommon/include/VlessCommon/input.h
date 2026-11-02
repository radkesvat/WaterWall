#pragma once

#include "wwapi.h"

enum
{
    kVlessUdpHeaderLen = 2
};

/* Gather only the UDP length prefix, leaving any body in its representation.
 * False preserves partial prefix progress; true publishes the body length.
 * The caller validates availability and takes the frame through its reader. */
bool vlessReadUdpHeader(buffer_reader_t *reader, uint16_t *body_length);
