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

#define HEAD_BUF_SZ 0x60

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
int base_ksymtab_kcrctab_ksymtabstrings(kern_dynamic *kernel_local_target)
{
#define TARGET_KSYMTAB_SEARCH_STR followStr
    int result = -1;
    named_kmap_t *head_text_shdr = 0;
    named_kmap_t *init_text_shdr = 0;
    named_kmap_t *text_shdr = 0;
    size_t kBuffer = 0;
    size_t searchSz = 0;
    char searchStr[] = "module.sig_enforce";
    char followStr[] = "nomodule";
    symsearch *tmpSymSearch = 0;
    uint16_t poststr_block = 0;
    binary_ss module_ss((uint8_t *)followStr, sizeof(followStr), 0, 1, true);
    binary_ss nullterm_ss((uint8_t *)&poststr_block, sizeof(poststr_block), 0, 1, true);

    bool live_kernel = kernel_local_target->is_live_kernel();
    size_t ksymtab_base = 0;
    size_t ksymtab_gpl_base = 0;
    size_t kcrctab_base = 0;
    size_t kcrctab_gpl_base = 0;
    size_t ksymtab_strings_base = 0;

    // check if all 3 already exists
    FINISH_IF((kernel_local_target->check_kmap("__ksymtab", NULL) == 0) &&
              (kernel_local_target->check_kmap("__kcrctab", NULL) == 0) &&
              (kernel_local_target->check_kmap("__ksymtab_strings", NULL) == 0));

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
    SAFE_BAIL(kernel_local_target->kernel_search(&module_ss, head_text_shdr->kva, searchSz, true, (void **)&kBuffer) == -1);

    kBuffer = kBuffer + sizeof(TARGET_KSYMTAB_SEARCH_STR);
    BIT_PAD(kBuffer, size_t, 8);

    SAFE_BAIL(kernel_local_target->live_kern_addr(kBuffer, sizeof(symsearch) * 3, (void **)&tmpSymSearch) == -1);

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

    SAFE_BAIL(kernel_local_target->kernel_search(&nullterm_ss, ksymtab_strings_base, init_text_shdr->kva - ksymtab_strings_base, true, (void **)&kBuffer) == -1);
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
    // this is a branch instruction, obviously fluctuates between devices
    0x146e0000,
    0x00080000,
    0x03102000, // this qword fluctuates between devices, this is the value for 3a, 4a is 0x2475000
    0x0000000a,
    0x00000000,
    0x00000000,
    0x00000000,
    0x644d5241,
    0x00000000,
    0x00000000,
    0x00000000,
    0x00000000,
};

unsigned long somecheck[] =
{
    0x00000000,
    0x00000000,
    0x00000000,
    0x644d5241
};

// debian
// Release:        10
// 4.19.0-20-arm64
int evaluate_found(uint8_t *buf)
{
    int result = -1;
    // hde_local instTemp;
    uint8_t *buftmp = buf;

    // SAFE_BAIL(CASE_ARM64_ENC(*(uint32_t*)buftmp, INSTCODE, BR_ENC) == 0);
    // buftmp += sizeof(uint32_t);
    // SAFE_BAIL(CASE_ARM64_ENC(*(uint32_t*)buftmp, INSTCODE, DPIMM_ENC) == 0);

    // ARMd@
    #if defined(DEBIAN)
    SAFE_BAIL(*(uint64_t *)(buf + 0x38) != 0x00000040644d5241);
    #elif defined(SARGO)
    SAFE_BAIL(*(uint64_t*)(buf + 0x38) != 0x00000000644d5241);
    #else
    #endif

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
int kBaseRoll(size_t *kbase_a)
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

int base_head_text(kernel_linux* kernel_local_target)
{
    int section_size = PAGE_SIZE4K;
    size_t otherbase = 0;

    FINISH_IF(
        (kernel_local_target->check_kmap(".head.text", NULL) == 0)
        );

#if defined(DEBIAN)
#endif

    otherbase = kernel_local_target->get_binbegin();

    kernel_local_target->insert_section(".head.text", otherbase, section_size);
    kernel_local_target->insert_section(".text", otherbase + section_size, 0);

finish:
    return 0;
}

int base_inits(kernel_linux* kernel_local_target)
{
    int result = -1;
    instSet getB(AARCH64_IBE);
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

    // getB.addNewInst(cOperand::createASI<size_t, size_t, saveVar_t>(SP, SP, getB.checkOperand(0)));
    // SAFE_BAIL(kernel_search(&getB, binBegin, PAGE_SIZE * 4, &text_start) == -1);

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


int base_ksymtab_strings_brute(kernel_linux* kernel_local_target)
{
// make sure we don't search memory forever
#define KSYMSTRASSUMESIZE   0x40000
#define INIT_TASK           "init_task"
    int result = -1;
    const char* curStr = 0;
    const char* prevStr = 0;
    size_t offsetTmp = 0;
    size_t paramSec_start = 0;
    int dbgCounter = 0;
    size_t ksymtabstr_tmp = 0;
    size_t ksymtabstr_sz = 0;
    named_kmap_t* text_map = 0;
    named_kmap_t* init_map = 0;
    char* init_text_str = 0;
    uint16_t zerobuf = 0;
    binary_ss init_text_ss((uint8_t *)INIT_TASK, sizeof(INIT_TASK), 0, 1, true);
    binary_ss nonzero_ss((uint8_t*)&zerobuf, sizeof(zerobuf), 0, 1, true);
    void* ksymstrBuf = 0;
    size_t ksyms_count = 0;

    // if we know where it begins.
    const char* targSymName = 0;
    size_t targSymLen = 0;
    const char* targSymEnd = (const char*)((size_t)targSymName + targSymLen - 1);

    // check if kcrc already exists
    FINISH_IF(
        (kernel_local_target->check_kmap("__ksymtab_strings", NULL) == 0)
        );

    // grab the base that i need
    SAFE_BAIL(kernel_local_target->check_kmap(".text", &text_map) == -1);
    SAFE_BAIL(kernel_local_target->check_kmap(".init.text", &init_map) == -1);

    SAFE_BAIL(init_text_ss.findPattern((uint8_t*)text_map->kmap_stats.alloc_base, text_map->kmap_stats.alloc_size, (void**)&init_text_str) == -1);

    // find end of the __ksymtab_strings
    SAFE_BAIL(nonzero_ss.findPattern((uint8_t*)init_text_str, (size_t)((text_map->kmap_stats.alloc_size + text_map->kmap_stats.alloc_base) - offsetTmp), (void**)&offsetTmp) == -1);

    paramSec_start = offsetTmp;
    offsetTmp = rfindnn((const char*)paramSec_start, DEFAULT_SEARCH_SIZE);
    SAFE_BAIL(offsetTmp == -1);
    curStr = (const char*)(paramSec_start - offsetTmp);
    dbgCounter = offsetTmp;

    while (dbgCounter < KSYMSTRASSUMESIZE)
    {
        ksyms_count++;

        // if we know the symbol that begins the table, such as static_key_initialized,
        // then this works just fine. if we don't, then just count on the rstrnlenu, which
        // there is a 50% chance will be off my 1.
        if (targSymName != 0)
        {
            if (rstrncmp(curStr, targSymEnd, targSymLen) == 0)
            {
                goto finish_eval;
            }
        }

        // here we hit something that invalidates the string. if so, roll forward til
        // we know why
        offsetTmp = rstrnlenu(curStr, DEFAULT_SEARCH_SIZE);
        // SAFE_BREAK(offsetTmp == -1);
        if (offsetTmp == -1)
        {
            while (true)
            {
                // found the character that breaks the string, likely started a kcrc
                if (*(uint8_t*)curStr > 0x7f)
                {
                    curStr++;
                    if (((size_t)curStr % 4) != 0)
                    {
                        // pad forward incase i'm in the middle of a kcrc
                        curStr = (const char*)(((size_t)curStr & (ssize_t)(-4)) + 4);
                    }
                    goto finish_eval;
                }
                curStr--;
            }
        }

        // you're at the last non null character, subtract the offset to get to the next
        // null character. add 1 so that you're string begins at the next non null character.
        curStr = curStr - offsetTmp;
        prevStr = curStr + 1;

        // printf("%s\n", prevStr);

        // subtract 1 so you can start at the next non null character, the last non null char.
        curStr -= 1;
        dbgCounter += offsetTmp;
    }
    goto fail;

finish_eval:
    ksymtabstr_tmp = (size_t)curStr;
    if (targSymName != 0)
    {
        ksymtabstr_tmp = (size_t)(curStr - targSymLen + 1);
    }
    ksymtabstr_sz = paramSec_start - ksymtabstr_tmp;
    ksymtabstr_tmp = (ksymtabstr_tmp - (size_t)text_map->kmap_stats.alloc_base) + text_map->kva;
    kernel_local_target->insert_section("__ksymtab_strings", ksymtabstr_tmp, ksymtabstr_sz);
    if (kernel_local_target->get_ksyms_count() == 0)
    {
        kernel_local_target->set_ksyms_count(ksyms_count);
    }

finish:
    result = 0;
fail:
    SAFE_FREE(ksymstrBuf);
    return result;
}

int base_kcrctab(kernel_linux* kernel_local_target)
{
    int result = -1;
    size_t crcCount = 0;
    uint32_t* crcIter = 0;
    named_kmap_t* ksymtabstr_map = 0;
    size_t ksyms_count = 0;
    size_t kcrc_addr = 0;

    // check if kcrc already exists
    FINISH_IF(kernel_local_target->check_kmap("__kcrctab", NULL) == 0);

    // grab the base that i need
    SAFE_BAIL(kernel_local_target->check_kmap("__ksymtab_strings", &ksymtabstr_map) == -1);

    ksyms_count = kernel_local_target->get_ksyms_count();
#if defined(DEBIAN)
    kcrc_addr = ksymtabstr_map->kva - ksyms_count * sizeof(uint32_t);
#elif defined(SARGO)
    crcIter = (uint32_t*)ksymtabstr_map->kmap_stats.alloc_base;
    while (true)
    {
        if (*crcIter == *(crcIter - 2))
        {
            ksyms_count = crcCount;
            crcIter++;
            kcrc_addr = ksymtabstr_map->kva - (size_t)crcIter;
            goto finish_eval;
        }
        crcCount++;
        crcIter--;
    }
    goto fail;
#endif

finish_eval:
    kernel_local_target->insert_section("__kcrctab", kcrc_addr, ksymtabstr_map->kva - kcrc_addr);

finish:
    result = 0;
fail:
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

    // instSet getB;
    // size_t start_kernelOff = 0;
    // uint32_t* modverAddr = 0;
    // size_t modverOff = 0;

    // getB.addNewInst(cOperand::createMWI<size_t, size_t>(1, 0x80c0));
    // getB.addNewInst(cOperand::createB<saveVar_t>(getB.checkOperand(0)));
    // SAFE_BAIL(getB.findPattern(__primary_switched_g, PAGE_SIZE, &start_kernel_g) == -1);

    // getB.getVar(0, &start_kernelOff);
    // start_kernel_g = (uint32_t*)(start_kernelOff + (size_t)start_kernel_g);

    // getB.clearInternals();
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

