#pragma once

#ifdef __cplusplus
extern "C"
{
#endif

// Length-Prefixed-Message

// flags:1byte + length:4bytes = 5bytes
#define GRPC_MESSAGE_HDLEN 5

    typedef struct
    {
        unsigned char flags;
        unsigned int  length;
    } grpc_message_hd;

    typedef struct
    {
        unsigned char  flags;
        unsigned int   length;
        unsigned char *message;
    } grpc_message;

    static inline void grpcMessageHdPack(const grpc_message_hd *restrict hd, unsigned char *restrict buf)
    {
        unsigned char *p = buf;
        // flags
        *p++ = hd->flags;
        // hton length
        unsigned int length = hd->length;
        *p++                = (length >> 24) & 0xFF;
        *p++                = (length >> 16) & 0xFF;
        *p++                = (length >> 8) & 0xFF;
        *p++                = length & 0xFF;
    }

    static inline void grpcMessageHdUnpack(grpc_message_hd *restrict hd, const unsigned char *restrict buf)
    {
        const unsigned char *p = buf;
        // flags
        hd->flags = *p++;
        // ntoh length
        hd->length = ((unsigned int) *p++) << 24;
        hd->length |= ((unsigned int) *p++) << 16;
        hd->length |= ((unsigned int) *p++) << 8;
        hd->length |= *p++;
    }

    // protobuf
    // tag = field_num << 3 | wire_type
    // varint(tag) [+ varint(length_delimited)] + value;
    typedef enum
    {
        kWireTypeVarint          = 0,
        kWireTypeFixeD64         = 1,
        kWireTypeLengthDelimited = 2,
        kWireTypeStartGroup      = 3,
        kWireTypeEndGroup        = 4,
        kWireTypeFixeD32         = 5,
    } wire_type;

    typedef enum
    {
        kFieldTypeDouble   = 1,
        kFieldTypeFloat    = 2,
        kFieldTypeInT64    = 3,
        kFieldTypeUinT64   = 4,
        kFieldTypeInT32    = 5,
        kFieldTypeFixeD64  = 6,
        kFieldTypeFixeD32  = 7,
        kFieldTypeBool     = 8,
        kFieldTypeString   = 9,
        kFieldTypeGroup    = 10,
        kFieldTypeMessage  = 11,
        kFieldTypeBytes    = 12,
        kFieldTypeUinT32   = 13,
        kFieldTypeEnum     = 14,
        kFieldTypeSfixeD32 = 15,
        kFieldTypeSfixeD64 = 16,
        kFieldTypeSinT32   = 17,
        kFieldTypeSinT64   = 18,
        kMaxFieldType      = 18,
    } field_type;

#define PROTOBUF_MAKE_TAG(field_number, wire_type) ((field_number) << 3 | (wire_type))
#define PROTOBUF_FILED_NUMBER(tag)                 ((tag) >> 3)
#define PROTOBUF_WIRE_TYPE(tag)                    ((tag) &0x07)

#ifdef __cplusplus
}
#endif
