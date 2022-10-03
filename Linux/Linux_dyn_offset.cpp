#include <stdint.h>
#include <stdio.h>

#include <localUtil.h>
#include <bgrep_e.h>
#include <ibeSet.h>
#include <krw_util.h>

#include <kernel_block.h>
#include <kern_img.h>
#include <kern_static.h>
#include <kern_dynamic.h>

#if defined(__arm64__) || defined(__aarch64__)
#include <hdeA64.h>
#define hde_local hdeA64_t
#elif defined(__x86_64__)
#include <hde.h>
#define hde_local hde64s_t
#endif

int base_init_text(kernel_linux* kernel_local_target)
{
    int result = -1;
    hde_local tempInst = {0};
    uint32_t* binBegMap = 0;
    size_t binBegin = 0;
    size_t slideval = 0;
    size_t initbase = 0;
    bool live_kernel = false;

    FINISH_IF(
        (kernel_local_target->check_kmap(".init.text", NULL) == 0)
        );

#if defined(DEBIAN)
    slideval = 4;
#elif defined(SARGO)
    slideval = 0;
#endif

    binBegin = kernel_local_target->get_binbegin();
    live_kernel = kernel_local_target->is_live_kernel();

    SAFE_BAIL(kernel_local_target->live_kern_addr(binBegin, sizeof(*binBegMap) * 2, (void**)&binBegMap) == -1);
    SAFE_BAIL(parseInst(*(uint32_t*)((size_t)binBegMap + slideval), &tempInst) == -1);
    initbase = tempInst.immLarge + binBegin + slideval;

    kernel_local_target->insert_section(".init.text", (size_t)initbase, 0);
    
finish:
    result = 0;
fail:
    SAFE_LIVE_FREE(binBegMap);
    return result;
}
