#pragma once


#define STRINGIFY(x) #x
#define TOSTRING(x) STRINGIFY(x)

char* concat(const char *s1, const char *s2);
