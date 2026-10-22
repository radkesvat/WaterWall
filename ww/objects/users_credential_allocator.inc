/* STC includes reset allocator macros after each map expansion. Wipe old
 * credential storage on rehash and destruction before returning it to the heap. */
#define i_malloc              c_malloc
#define i_calloc              c_calloc
#define i_realloc             c_realloc
#define i_free(pointer, size) usersCredentialIndexFree((pointer), (size_t) (size))
