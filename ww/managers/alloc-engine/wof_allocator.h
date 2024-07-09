/* Wheel-of-Fortune Memory Allocator
 * Copyright 2013, Evan Huus <eapache@gmail.com>
 */

#ifndef __WOF_ALLOCATOR_H__
#define __WOF_ALLOCATOR_H__

#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

typedef struct _wof_allocator_t wof_allocator_t;

void *
wof_alloc(wof_allocator_t *allocator, const size_t size);

void
wof_free(wof_allocator_t *allocator, void *ptr);

void *
wof_realloc(wof_allocator_t *allocator, void *ptr, const size_t size);

void
wof_free_all(wof_allocator_t *allocator);

void
wof_gc(wof_allocator_t *allocator);

void
wof_allocator_destroy(wof_allocator_t *allocator);

wof_allocator_t *
wof_allocator_new(void);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __WOF_ALLOCATOR_H__ */
