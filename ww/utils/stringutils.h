#pragma once

#ifndef STRINGIFY
#define STRINGIFY(x) #x
#endif
#define TOSTRING(x) STRINGIFY(x)

char *concat(const char *s1, const char *s2);
void toUpperCase(char *str);
void toLowerCase(char *str);
