#ifndef WATERWALL_XZ_FORMAT_H
#define WATERWALL_XZ_FORMAT_H

/* Waterwall's private stream identifiers. The remaining XZ layout is unchanged.
 * The encoder and decoder share these bytes; neither terminating NUL is stored. */
#define WW_XZ_HEADER_MAGIC      "MUFASA"
#define WW_XZ_HEADER_MAGIC_SIZE 6
#define WW_XZ_FOOTER_MAGIC      "gg"
#define WW_XZ_FOOTER_MAGIC_SIZE 2

/* On-disk CRC32 selector. Stream CRCs still cover the standard 00 01 flags. */
#define WW_XZ_CRC32_MARKER 0xff

/* These fields have fixed widths in the stream layout, including CRC offsets. */
typedef char ww_xz_header_magic_width[(sizeof(WW_XZ_HEADER_MAGIC) - 1 == WW_XZ_HEADER_MAGIC_SIZE) ? 1 : -1];
typedef char ww_xz_footer_magic_width[(sizeof(WW_XZ_FOOTER_MAGIC) - 1 == WW_XZ_FOOTER_MAGIC_SIZE) ? 1 : -1];

#endif
