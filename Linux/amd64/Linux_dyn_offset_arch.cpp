#include <ibeSet.h>

#include <kernel_block.h>
#include <kern_img.h>
#include <kern_static.h>
#include <kern_dynamic.h>

#include <hde.h>
#include <amd64/opcOp_arch.h>
#define hde_local hde64s_t
#define immMain imm
typedef instSet<cOperand_amd64, val_set_X86_t> instSetA;
typedef cOperand_amd64::saveVar_t saveVar_t;

int task_struct_tasks(kernel_linux* kernel_local_target)
{
    int result = -1;
    size_t send_sig = 0;
    void* result_addr = 0;
    size_t var_tmp = 0;
    named_kmap_t* text_section = 0;
    instSetA getB;

    SAFE_PAIL(1, "not implemented");

    SAFE_BAIL(kernel_local_target->ksym_dlsym("send_sig_all", &send_sig) == -1);

    SAFE_BAIL(kernel_local_target->check_kmap(".text", &text_section) == -1);

    getB.clearInternals();

    // getB.addNewInst(cOperand_arm64::createLDRB<saveVar_t, saveVar_t, saveVar_t>(getB.checkOperand(0), getB.checkOperand(0), getB.checkOperand(1)));
    SAFE_BAIL(getB.findPattern((send_sig - text_section->kva) + text_section->kmap_stats.alloc_base, PAGE_SIZE4K, &result_addr) == -1);

    getB.getVar(1, &var_tmp);
    kernel_local_target->kern_sym_insert("task_struct.tasks", var_tmp);

    result = 0;
fail:
    return result;
}

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
#endif

    binBegin = kernel_local_target->get_binbegin();
    live_kernel = kernel_local_target->is_live_kernel();

    SAFE_BAIL(kernel_local_target->live_kern_addr(binBegin, sizeof(*binBegMap) * 2, (void**)&binBegMap) == -1);
    SAFE_BAIL(parseInst((uint8_t*)((size_t)binBegMap + slideval), &tempInst) == -1);
    initbase = tempInst.immMain + binBegin + slideval;

    kernel_local_target->insert_section(".init.text", (size_t)initbase, 0);
    
finish:
    result = 0;
fail:
    SAFE_LIVE_FREE(binBegMap);
    return result;
}
