#include <stdint.h>
#include <stdio.h>

#include <localUtil.h>

#include <kernel_block.h>
#include <kern_img.h>
#include <kern_static.h>
#include <kern_dynamic.h>

#include "../heuristic_routines.h"

#include <finddyn.h>

#ifndef RESOLVE_HEURISTICS
#define RESOLVE_HEURISTICS
#endif

int finddyn(kernel_linux* kernel_local_target)
{
    int result = -1;

    RESOLVE_HEURISTICS

    result = 0;
fail:
    return result;
}