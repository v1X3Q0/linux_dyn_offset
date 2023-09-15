#include <stdint.h>
#include <stdio.h>

#include <localUtil.h>
#include <bgrep_e.h>
#include <ibeSet.h>
#include <kernel_block.h>
#include <kern_img.h>
#include <kern_static.h>
#include <kern_dynamic.h>

int grab_task_struct_offs(kern_dynamic* kernel_local_target)
{
    int result = -1;
    size_t init_task = 0;
    void* init_task_mapped = 0;
    size_t* memberIter = 0;
    size_t pushable_tasks = 0;
    size_t tasks = 0;
    bool live_kernel = kernel_local_target->is_live_kernel();

    SAFE_BAIL(kernel_local_target->ksym_dlsym("init_task", &init_task) == -1);
    SAFE_BAIL(kernel_local_target->live_kern_addr(init_task, PAGE_SIZE, &init_task_mapped) == -1);

    memberIter = (size_t*)init_task_mapped;
    for (int i = 0; i < PAGE_SIZE; i += 8)
    {
        int curIter = i / sizeof(size_t);
        
        if (
            (memberIter[curIter] == memberIter[curIter + 1]) &&
            (memberIter[curIter + 2] == memberIter[curIter + 3]) &&
            (memberIter[curIter] != 0) &&
            (memberIter[curIter + 2] != 0)
            )
        {
            // we are at task->pushable_tasks.prio_list, so the base of a
            // plist_node is at current - 8, the size of prio, plist_node's
            // first member. then subtract the size of another list to get
            // the offset for the tasks structure.
            pushable_tasks = i - sizeof(size_t) * 1;
            tasks = i - sizeof(size_t) * 3;
            goto found;
        }
    }
    goto fail;

found:
    kernel_local_target->kern_off_insert("task_struct.tasks", tasks);
    kernel_local_target->kern_off_insert("task_struct.pushable_tasks", pushable_tasks);

    result = 0;
fail:
    SAFE_LIVE_FREE(init_task_mapped);
    return result;
}

