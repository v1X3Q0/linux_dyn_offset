#include <stdint.h>
#include <stdio.h>

#include <localUtil.h>
#include <bgrep_e.h>
#include <hdeA64.h>
#include <ibeSet.h>
#include <kernel_block.h>
#include <kern_img.h>
#include <kern_static.h>

int grab_primary_switch(kernel_linux* kernel_local_target)
{
    int result = -1;
    instSet getB;
    uint32_t* primSwitchBAddr = 0;
    size_t primSwitchOff = 0;

    getB.addNewInst(cOperand::createB<saveVar_t>(getB.checkOperand(0)));
    SAFE_BAIL(kernel_local_target->kernel_search(&getB,
        kernel_local_target->KSYM_VS(_sinittext), PAGE_SIZE, (void**)&primSwitchBAddr) == -1);

    getB.getVar(0, &primSwitchOff);
    kernel_local_target->KSYM_VS(__primary_switch) = primSwitchOff + (size_t)primSwitchBAddr;
    
    result = 0;
fail:
    return result;
}

int grab_primary_switched(kernel_linux* kernel_local_target)
{
    int result = -1;
    instSet getB;
    uint32_t* primSwitchedLdrAddr = 0;
    size_t primSwitchOff = 0;
    uint32_t* create_page_tablesAddr = 0;
    size_t create_page_tablesOff = 0;

    uint32_t* __primary_switched;

// the old way,was find a particular branch, resolve the math for an ldr and
// afterwards add it to the found address. changed to resolving an adjacent
// routine and looking for a prologue.
    // size_t tmpMath = 0;

    // operand 1 is the immediate19, operand 2 is the register
    // getB.addNewInst(cOperand::createLDRL<saveVar_t, saveVar_t>(getB.checkOperand(0), getB.checkOperand(1)));
    // SAFE_BAIL(getB.findPattern(__primary_switch_g, PAGE_SIZE, &primSwitchedLdrAddr) == -1);

    // getB.getVar(1, &primSwitchOff);

    // tmpMath = *(size_t*)(primSwitchOff + (size_t)primSwitchedLdrAddr);
    // __primary_switched_g = (uint32_t*)(tmpMath + (size_t)binBegin);

    getB.addNewInst(new cOperand(ARM64_ISB_OP));
    getB.addNewInst(cOperand::createBL<saveVar_t>(getB.checkOperand(0)));
    SAFE_BAIL(kernel_local_target->kernel_search(&getB,
        kernel_local_target->KSYM_VS(__primary_switch), PAGE_SIZE, (void**)&create_page_tablesAddr) == -1);

    getB.getVar(0, &create_page_tablesOff);
    KSYM_V(__create_page_tables) = create_page_tablesOff + (size_t)create_page_tablesAddr + sizeof(uint32_t);
    
    getB.clearInternals();
    getB.addNewInst(cOperand::createADRP<saveVar_t, saveVar_t>(getB.checkOperand(0), getB.checkOperand(1)));
    getB.addNewInst(cOperand::createASI<size_t, saveVar_t, size_t>(SP, getB.checkOperand(0), 4));
    SAFE_BAIL(kernel_local_target->kernel_search(&getB,
        kernel_local_target->KSYM_V(__create_page_tables), PAGE_SIZE, (void**)&__primary_switched) == -1);
    KSYM_V(__primary_switched) = (size_t)__primary_switched;

    result = 0;
fail:
    return result;
}

int grab_start_kernel_g()
{
    int result = -1;
    instSet getB;
    size_t start_kernelOff = 0;

    uint32_t* start_kernel;

    getB.addNewInst(cOperand::createB<saveVar_t>(getB.checkOperand(0)));
    SAFE_BAIL(kernel_search(&getB, KSYM_V(__primary_switched), PAGE_SIZE, (void**)&start_kernel) == -1);

    getB.getVar(0, &start_kernelOff);
    KSYM_V(start_kernel) = start_kernelOff + (size_t)start_kernel;

finish:
    result = 0;
fail:
    return result;
}

