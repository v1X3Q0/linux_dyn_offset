#include <stdint.h>
#include <stdio.h>

#include <localUtil.h>
#include <bgrep_e.h>
#include <krw_util.h>

#include <kernel_block.h>
#include <kern_img.h>
#include <kern_static.h>
#include <kern_dynamic.h>

int task_struct_comm(kernel_linux* kernel_local_target)
{
    int result = -1;
    void* result_addr = 0;
    uint64_t var_tmp = 0;
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
