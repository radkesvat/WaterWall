WW eventloop is a fork of the awesome [libhv](https://github.com/ithewei/libhv)

which directly builds with WW lib internally

# changes:

removed most of the things we did not use in waterwall

waterwall is a pure c library, so removed every c++ related code (c++ evpp and apps)

removed all examples

removed ssl parts

removed unpack and other stream related code

removed thread safety parts of hio_t structure

added small changes such as splice call support (not yet integrated into waterwall)

effort to change loop buffer to ww/buffer_pool


