#pragma once
#include "wlibc.h"

/*
    This object is supposed to be kept on stack, but in can have allocated pointer,
    therefore it is required to call dynamicvalueDestroy
*/

enum dynamic_value_status
{
    kDvsEmpty = 0x0,
    kDvsConstant,
    kDvsFirstOption,
    kDvsMappedOption1,
    kDvsMappedOption2,
    kDvsMappedOption3,
    kDvsMappedOption4,
    kDvsMappedOption5
};

typedef struct dynamic_value_s
{
    uint32_t status; // enum dynamic_value_status
    uint32_t integer;
    void    *string;
} dynamic_value_t;

static void dynamicvalueDestroy(const dynamic_value_t dy)
{
    if (dy.string)
    {
        memoryFree(dy.string);
    }
}
