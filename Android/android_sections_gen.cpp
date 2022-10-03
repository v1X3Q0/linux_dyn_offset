#include <stdint.h>
#include <stdio.h>

#include <localUtil.h>
#include <bgrep_e.h>
#include <hdeA64.h>
#include <ibeSet.h>
#include <kernel_block.h>
#include <kern_img.h>
#include <kern_static.h>
#include <kern_dynamic.h>

int grab_sinittext(kern_static* kernel_local_target)
{
    int result = -1;
    hde_t tempInst = {0};
    uint32_t* binBegMap = 0;
    
    SAFE_BAIL(live_kern_addr(binBegin, sizeof(*binBegMap), (void**)&binBegMap) == -1);
    SAFE_BAIL(parseInst(*binBegMap, &tempInst) == -1);
    KSYM_V(_sinittext) = tempInst.immLarge + binBegin;

    result = 0;
fail:
    SAFE_LIVE_FREE(binBegMap);
    return result;
}
