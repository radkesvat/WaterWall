#pragma once

/*
    This object is supposed to be kept on stack, but in can have allocated pointer,
    therefore it is required to call destroyDynamicValue 
*/

typedef struct dynamic_value_s
{
    enum dynamic_value_status status;
    size_t                    value;
    void                     *value_ptr;
} dynamic_value_t;




void destroyDynamicValue(const dynamic_value_t dy)
{
    if (dy.value_ptr)
    {
        memoryFree(dy.value_ptr);
    }
}

