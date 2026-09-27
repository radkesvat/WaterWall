#pragma once
#include "devices/device_reader_session.h"

/* Final-reference cleanup, after all message and token references settled. */
void deviceReaderDispatchDestroy(device_reader_session_t *session);
