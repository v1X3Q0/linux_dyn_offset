
#include <ibeSet.h>

#include <hdeA64.h>
#include "arm64/opcOp_arch.h"
#define hde_local hdeA64_t
typedef instSet<cOperand_arm64, val_set_A64_t> instSetA;
#define IBE_LOCAL AARCH64_IBE

int base_inits(kernel_linux* kernel_local_target)
{
    int result = -1;
    instSetA getB(IBE_LOCAL);
    uint32_t* text_start = 0;
    named_kmap_t* head_map = 0;
    named_kmap_t* init_map = 0;
    uint32_t nonzeroLook = 0;
    size_t binBegin = 0;
    binary_ss* nonzero_ss = 0;
    size_t sinittext_tmp = 0;
    
    FINISH_IF(
        (kernel_local_target->check_kmap(".head.text", NULL) == 0) &&
        (kernel_local_target->check_kmap(".text", NULL) == 0)
        );

    SAFE_BAIL(kernel_local_target->check_kmap(".init.text", &init_map) == -1);
    
    sinittext_tmp = init_map->kva;
    binBegin = kernel_local_target->get_binbegin();
    // SO originally i searched for the first sub sp operation. HOWEVER it seems like on different
    // devices and kernels the first routine may not even start with a sub, but rather an stp.
    // if this is the case.... well gonna be harder to detect. so another option is either looking for
    // page, or first nonzero word after 0x40, gonna stick with the latter.

    getB.addNewInst(cOperand::createASI<size_t, size_t, saveVar_t>(SP, SP, getB.checkOperand(0)));
    SAFE_BAIL(kernel_search(&getB, binBegin, PAGE_SIZE * 4, &text_start) == -1);

#if defined(DEBIAN)
    text_start = (uint32_t*)(binBegin + PAGE_SIZE4K);
#elif defined(SARGO)
    nonzero_ss = new binary_ss((uint8_t*)&nonzeroLook, sizeof(nonzeroLook), 0x40, sizeof(nonzeroLook), false);
    SAFE_BAIL(kernel_local_target->kernel_search(&nonzero_ss, binBegin, PAGE_SIZE * 2, (void**)&text_start) == -1);
#endif

    kernel_local_target->insert_section(".head.text", (size_t)binBegin, (size_t)text_start - binBegin);
    kernel_local_target->insert_section(".text", (size_t)text_start, sinittext_tmp - (size_t)text_start);
    
finish:
    result = 0;
fail:
    SAFE_DEL(nonzero_ss);
    return result;
}

int base_ksymtab(kernel_linux* kernel_local_target)
{
    // here is asspull city.... gonna look for a hella regex. in execution, the routine
    // _request_firmware has a call to kmem_cache_alloc_trace(kmalloc_caches[0][7], 0x14080C0u, 0x20uLL);
    // where args 2 and 3 are the gfp flags and size. because i believe them to be measurable enough,
    // as well as arguments, lets give them a looksie....

    int result = -1;
    size_t ksymtabTmp = 0;
    named_kmap_t* crcSec = 0;
    size_t ksym_size = sizeof(kernel_symbol);
    size_t ksyms_count = 0;
    instSetA getB;
    size_t start_kernelOff = 0;
    uint32_t* modverAddr = 0;
    size_t modverOff = 0;
    uint32_t* __primary_switched;

    // check if ksymtab already exists
    FINISH_IF(kernel_local_target->check_kmap("__ksymtab", NULL) == 0);

    // grab the base that i need
    SAFE_BAIL(kernel_local_target->check_kmap("__kcrctab", &crcSec) == -1);

    ksyms_count = kernel_local_target->get_ksyms_count();
    SAFE_BAIL(ksyms_count == 0);

#if defined(DEBIAN)
    ksym_size = sizeof(kernel_symbol_relative);
#elif defined(SARGO)
#endif
    ksymtabTmp = crcSec->kva - (ksym_size * ksyms_count);
    kernel_local_target->insert_section("__ksymtab", ksymtabTmp, crcSec->kva - ksymtabTmp);

    getB.addNewInst(cOperand::createMWI<size_t, size_t>(1, 0x80c0));
    getB.addNewInst(cOperand::createB<saveVar_t>(getB.checkOperand(0)));
    SAFE_BAIL(getB.findPattern(__primary_switched, PAGE_SIZE, &start_kernel_g) == -1);

    getB.getVar(0, &start_kernelOff);
    start_kernel_g = (uint32_t*)(start_kernelOff + (size_t)start_kernel_g);

    getB.clearInternals();
    getB.addNewInst(cOperand::createADRP<saveVar_t, saveVar_t>(getB.checkOperand(0), getB.checkOperand(1)));
    getB.addNewInst(cOperand::createADRP<saveVar_t, saveVar_t>(getB.checkOperand(2), getB.checkOperand(3)));
    getB.addNewInst(cOperand::createASI<saveVar_t, saveVar_t, saveVar_t>(getB.checkOperand(0), getB.checkOperand(0), getB.checkOperand(4)));
    getB.addNewInst(cOperand::createASI<saveVar_t, saveVar_t, saveVar_t>(getB.checkOperand(2), getB.checkOperand(2), getB.checkOperand(5)));
    getB.addNewInst(cOperand::createLI<saveVar_t, size_t, size_t, size_t>(getB.checkOperand(6), X31,  0x39, 0x3));

finish:
    result = 0;
fail:
    return result;
}
