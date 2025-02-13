The eventloop port of libWW was originally a fork of the awesome [libhv](https://github.com/ithewei/libhv)

which is now merged and uses buffer and thread local pools of libWW

# some changes made to event loop:

removed thread safety parts of wio_t, forcing thread local behaviour

small optimization tweaks

added changes such as splice call support (not yet integrated into waterwall)

using hybrid mutex of libWW instead of normal mutex

changed the use of localtime() to localtime_r() (helgrind no longer shouts)

modified many parts of the source to support -pedantic compile flag, and other flags that we have enabled in libWW.

logging structure changed, it will no longer use macros ( compiler exensions ), and needs a header and source file for each logger

changed the behaviour of network handling and removed most of controlling & shrink conditions  


