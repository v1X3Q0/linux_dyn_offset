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
    uint32_t* __primary_switched = 0;
    uint32_t* start_kernel = 0;

    // check if ksymtab already exists
    FINISH_IF(kernel_local_target->check_kmap("__ksymtab", NULL) == 0);

    // grab the base that i need
    SAFE_BAIL(kernel_local_target->check_kmap("__kcrctab", &crcSec) == -1);

    ksyms_count = kernel_local_target->get_ksyms_count();
    SAFE_BAIL(ksyms_count == 0);

    SAFE_PAIL(1, "amd64 not implemented");

    ksym_size = sizeof(kernel_symbol_relative);
    ksymtabTmp = crcSec->kva - (ksym_size * ksyms_count);
    kernel_local_target->insert_section("__ksymtab", ksymtabTmp, crcSec->kva - ksymtabTmp);

    // getB.addNewInst(cOperand::createMWI<size_t, size_t>(1, 0x80c0));
    // getB.addNewInst(cOperand::createB<saveVar_t>(getB.checkOperand(0)));
    SAFE_BAIL(getB.findPattern((uint8_t*)__primary_switched, PAGE_SIZE, (void**)&start_kernel) == -1);

    getB.getVar(0, &start_kernelOff);
    start_kernel = (uint32_t*)(start_kernelOff + (size_t)start_kernel);

    getB.clearInternals();
    // getB.addNewInst(cOperand::createADRP<saveVar_t, saveVar_t>(getB.checkOperand(0), getB.checkOperand(1)));
    // getB.addNewInst(cOperand::createADRP<saveVar_t, saveVar_t>(getB.checkOperand(2), getB.checkOperand(3)));
    // getB.addNewInst(cOperand::createASI<saveVar_t, saveVar_t, saveVar_t>(getB.checkOperand(0), getB.checkOperand(0), getB.checkOperand(4)));
    // getB.addNewInst(cOperand::createASI<saveVar_t, saveVar_t, saveVar_t>(getB.checkOperand(2), getB.checkOperand(2), getB.checkOperand(5)));
    // getB.addNewInst(cOperand::createLI<saveVar_t, size_t, size_t, size_t>(getB.checkOperand(6), X31,  0x39, 0x3));

finish:
    result = 0;
fail:
    return result;
}
