#pragma once
#include <stdio.h>

#ifndef NDEBUG
#define ERR(...) fprintf(stderr, __VA_ARGS__)
#else
#define ERR(...) 
#endif
