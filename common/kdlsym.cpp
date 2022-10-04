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

#if defined(DEBIAN)
    #define kernel_symbol_t kernel_symbol_relative
#elif defined(SARGO)
    #define kernel_symbol_t kernel_symbol
#endif

int ksym_dlsym_kcrc(kernel_linux* kernel_local_target, const char* newString, size_t* out_address)
{
    int result = -1;
    const char* kstrBase = 0;
    const char* kstrIter = 0;
    named_kmap_t* ksymSec = 0;
    named_kmap_t* ksymgplSec = 0;
    named_kmap_t* ksymstrSec = 0;
    kernel_symbol_t* ksymIter = 0;
    size_t nametmp = 0;
    size_t valuetmp = 0;

    // get dependencies, we need the ksymtab_str for comparison and the ksymtab has the
    // out value for us.
    SAFE_BAIL(kernel_local_target->check_kmap("__ksymtab", &ksymSec) == -1);
    SAFE_BAIL(kernel_local_target->check_kmap("__ksymtab_gpl", &ksymgplSec) == -1);
    SAFE_BAIL(kernel_local_target->check_kmap("__ksymtab_strings", &ksymstrSec) == -1);

    ksymIter = (kernel_symbol_t*)ksymSec->kmap_stats.alloc_base;
    kstrBase = (const char*)ksymstrSec->kmap_stats.alloc_base;
    // SAFE_BAIL(live_kern_addr(UNRESOLVE_REL(ksymSec->sh_offset), ksymSec->sh_size + ksymgplSec->sh_size, (void**)&ksymIter) == -1);
    // SAFE_BAIL(live_kern_addr(UNRESOLVE_REL(ksymstrSec->sh_offset), ksymstrSec->sh_size, (void**)&kstrBase) == -1);
    // strIter = (const char*)UNRESOLVE_REL(ksymstrSec->sh_offset);

    for (int i = 0; i < kernel_local_target->get_ksyms_count(); i++)
    {
#if defined(DEBIAN)
        nametmp = (ssize_t)ksymIter[i].name_offset + ((ssize_t)&(ksymIter[i].name_offset) - (ssize_t)ksymSec->kmap_stats.alloc_base) + ksymSec->kva;
        valuetmp = (ssize_t)ksymIter[i].value_offset + ((ssize_t)&(ksymIter[i].value_offset) - (ssize_t)ksymSec->kmap_stats.alloc_base) + ksymSec->kva;
#elif defined(SARGO)
        nametmp = ksymIter[i].name;
        valuetmp = ksymIter[i].value;
#endif
        // resolve against the base of the ksymtab so we can add to the kstrbase
        kstrIter = (const char*)((nametmp - (size_t)ksymstrSec->kva) + (size_t)kstrBase);
        if (strcmp(newString, kstrIter) == 0)
        {
            if (out_address != 0)
            {
                *out_address = valuetmp;
            }
            goto found;
        }
    }
    goto fail;

found:
    result = 0;
fail:
    return result;
}

