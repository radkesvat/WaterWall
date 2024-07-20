#pragma once
#include <stdint.h>
#include "shiftbuffer.h"

enum
{
    kMuxFlagOpen  = 0,
    kMuxFlagClose = 1,
    kMuxFlagFlow  = 2,
    kMuxFlagData  = 3
};

typedef uint16_t cid_t;

typedef struct __attribute__((__packed__))
{
    uint16_t length;
    cid_t    cid;
    uint8_t  flags;

    char data[];

} mux_frame_t;

static void makeOpenFrame(shift_buffer_t * buf,cid_t cid){
    shiftl(buf, sizeof(mux_frame_t));
    mux_frame_t frame = {
        .length = sizeof(mux_frame_t) - sizeof(frame.length),
        .cid = cid,
        .flags = kMuxFlagOpen
    };
    writeRaw(buf, &frame, sizeof(mux_frame_t));

}

static void makeCloseFrame(shift_buffer_t * buf,cid_t cid){
    shiftl(buf, sizeof(mux_frame_t));
    mux_frame_t frame = {
        .length = sizeof(mux_frame_t) - sizeof(frame.length),
        .cid = cid,
        .flags = kMuxFlagClose
    };
    writeRaw(buf, &frame, sizeof(mux_frame_t));
}

static void makeDataFrame(shift_buffer_t * buf,cid_t cid){
    shiftl(buf, sizeof(mux_frame_t));
    mux_frame_t frame = {
        .length = sizeof(mux_frame_t) - sizeof(frame.length),
        .cid = cid,
        .flags = kMuxFlagData
    };
    writeRaw(buf, &frame, sizeof(mux_frame_t));
}

