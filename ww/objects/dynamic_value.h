#pragma once

/*
 * Lightweight tagged value holder with optional owned string memory.
 */

#include "wlibc.h"

/*
    This object is supposed to be kept on stack, but it can have allocated pointer,
    therefore it is required to call dynamicvalueDestroy
*/

enum dynamic_value_status
{
    kDvsEmpty = 0x0,
    kDvsConstant,
    kDvsFirstOption,
    kDvsSecondOption,
    kDvsThirdOption,
    kDvsFourthOption,
    kDvsFifthOption
};

typedef struct dynamic_value_s
{
    uint32_t status; // enum dynamic_value_status
    uint32_t integer;
    void    *string;
} dynamic_value_t;

/**
 * @brief Release memory owned by a dynamic value.
 *
 * @param dy Value to destroy.
 */
static void dynamicvalueDestroy(const dynamic_value_t dy)
{
    if (dy.string)
    {
        memoryFree(dy.string);
    }
}
