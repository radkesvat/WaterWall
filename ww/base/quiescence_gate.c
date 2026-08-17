#include "quiescence_gate.h"

#ifndef NDEBUG
thread_local quiescence_gate_thread_entries_t quiescence_gate_thread_entries;
#endif
