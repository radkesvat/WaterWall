WW eventloop is a fork of the awesome [libhv](https://github.com/ithewei/libhv)

which directly builds with WW lib internally

# changes:

removed most of the things we did not use in waterwall

waterwall is a pure c library, so removed every c++ related code (c++ evpp and apps)

removed all examples

removed ssl parts

removed unpack, kcp, rudp support and other stream control related code

removed thread safety parts of wio_t structure (i mean the writelock), 
so we can no longer write to a wio_t from multiple threads

small optimization tweaks

added changes such as splice call support (not yet integrated into waterwall)

changed loop buffer to ww/buffer_pool and integrated thread local pools

added hybridmutex and used it instead of regular mutex , Lsema (light weight semaphore), thread channels

changed the use of localtime() to localtime_r() (helgrind no longer shouts)

modified many parts of the source to support -pedantic compile flag, and other flags that we have enabled in ww.

logging structure changed, it will no longer use macros ( compiler exensions )



note that this fork uses more memory since most of the memory controlling & shrink conditions removed

