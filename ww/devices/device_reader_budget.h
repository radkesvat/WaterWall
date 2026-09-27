#pragma once
#include "devices/device_reader_session.h"

/* Internal budget/wakeup boundary. Public reservation APIs remain in session.h. */
void deviceReaderSessionSignalOutputCapacity(device_reader_session_t *session);
bool deviceReaderSessionWaitReserveWork(device_reader_session_t *session, size_t charge, unsigned int packets,
                                        uint32_t generation);
void deviceReaderBudgetDestroy(device_reader_session_t *session);
