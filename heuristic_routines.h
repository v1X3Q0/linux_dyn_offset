#pragma once

int base_init_text(kernel_linux* kernel_local_target);
int base_head_text(kernel_linux* kernel_local_target);
int base_inits(kernel_linux* kernel_local_target);
int base_kcrctab(kernel_linux* kernel_local_target);
int base_ksymtab_strings_brute(kernel_linux* kernel_local_target);
int base_ksymtab(kernel_linux* kernel_local_target);
