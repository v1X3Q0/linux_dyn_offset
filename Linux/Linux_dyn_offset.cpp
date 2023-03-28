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

#include <kernel_block.h>
#if defined(__arm64__) || defined(__aarch64__)
#include <hdeA64.h>
#include <arm64/opcOp_arch.h>
#define hde_local hdeA64_t
#elif defined(__x86_64__)
#include <hde.h>
#include <amd64/opcOp_arch.h>
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

int task_struct_tasks(kernel_linux* kernel_local_target)
{
    int result = -1;
    size_t send_sig = 0;
    void* result_addr = 0;
    size_t var_tmp = 0;
    named_kmap_t* text_section = 0;
    instSet getB(AARCH64_IBE);
    
    SAFE_BAIL(kernel_local_target->ksym_dlsym("send_sig_all", &send_sig) == -1);

    SAFE_BAIL(kernel_local_target->check_kmap(".text", &text_section) == -1);

    getB.clearInternals();
    getB.addNewInst(cOperand_arm64::createLDRB<saveVar_t, saveVar_t, saveVar_t>(getB.checkOperand(0), getB.checkOperand(0), getB.checkOperand(1)));

    SAFE_BAIL(getB.findPattern((send_sig - text_section->kva) + text_section->kmap_stats.alloc_base, PAGE_SIZE4K, &result_addr) == -1);

    getB.getVar(1, &var_tmp);
    kernel_local_target->kern_sym_insert("task_struct.tasks", var_tmp);

    result = 0;
fail:
    return result;
}

int task_struct_comm(kernel_linux* kernel_local_target)
{
    int result = -1;
    void* result_addr = 0;
    size_t var_tmp = 0;
    // char swapperstr[] = "swapper\\0";
    uint64_t swapperstr[] = {0x2f72657070617773, 0x0000000000000030};
    binary_ss swapper_ss((uint8_t *)swapperstr, sizeof(swapperstr), 0, 1, true);
    
    SAFE_BAIL(kernel_local_target->ksym_dlsym("init_task", &var_tmp) == -1);
    SAFE_BAIL(kernel_local_target->kernel_search(&swapper_ss, var_tmp, PAGE_SIZE, (void**)&result_addr) == -1);

    var_tmp = (size_t)result_addr - var_tmp;
    kernel_local_target->kern_sym_insert("task_struct.comm", var_tmp);

    result = 0;
fail:
    return result;
}
