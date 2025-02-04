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
    enum dynamic_value_status status;
    size_t                    value;
    void                     *value_ptr;
} dynamic_value_t;




static void dynamicvalueDestroy(const dynamic_value_t dy)
{
    if (dy.value_ptr)
    {
        memoryFree(dy.value_ptr);
    }
}

