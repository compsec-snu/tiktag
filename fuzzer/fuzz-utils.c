#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#define PACKAGE
#define PACKAGE_VERSION
#include <dis-asm.h>
#include "mte-fuzz.h"

int libopcodes_disassemble(uint32_t insn, char *disas_str,
                           size_t disas_str_size)
{
    stream_state ss = {};

    // Set up the disassembler
    disassemble_info disasm_info = {};
    init_disassemble_info(&disasm_info, &ss, (fprintf_ftype) disas_sprintf);

    disasm_info.arch = bfd_arch_aarch64;
    disasm_info.mach = bfd_mach_aarch64;

    disasm_info.read_memory_func = buffer_read_memory;
    
    disasm_info.buffer = &insn;
    disasm_info.buffer_length = 4;
    disasm_info.buffer_vma = 0;

    disassemble_init_for_target(&disasm_info);

    disassembler_ftype disasm;
    disasm = disassembler(disasm_info.arch, false, disasm_info.mach, NULL);

    if (disasm == NULL) {
        fprintf(stderr, "libopcodes returned no disassembler. "
                "Has it been compiled with Armv8 support?\n");
        return 0;
    }

    // Actually do the disassembly
    size_t insn_size = disasm(0, &disasm_info);
    assert(insn_size == 4);

    // Store the resulting string
    snprintf(disas_str, disas_str_size, "%s", ss.buffer);

    ss.reenter = false;
    free(ss.buffer);

    return insn_size;
}

/*
 * From
 *  https://blog.yossarian.net/2019/05/18/Basic-disassembly-with-libopcodes
 */
int disas_sprintf(void *stream, const char *fmt, ...) {
    stream_state *ss = (stream_state *)stream;

    int n;
    va_list arg;
    va_start(arg, fmt);

    if (!ss->reenter) {
        n = vasprintf(&ss->buffer, fmt, arg);
        ss->reenter = true;
    } else {
        char *tmp;
        n = vasprintf(&tmp, fmt, arg);

        if (n == -1)
            return 1;

        char *tmp2;
        n = asprintf(&tmp2, "%s%s", ss->buffer, tmp);

        if (n != -1)
            free(tmp);

        free(ss->buffer);
        ss->buffer = tmp2;
    }
    va_end(arg);

    return 0;
}

void print_registers(struct user_regs_struct *regs) {
    printf("Registers:\n");
    printf("x0: %llx\n", regs->regs[0]);
    printf("x1: %llx\n", regs->regs[1]);
    printf("x2: %llx\n", regs->regs[2]);
    printf("x3: %llx\n", regs->regs[3]);
    printf("x4: %llx\n", regs->regs[4]);
    printf("x5: %llx\n", regs->regs[5]);
    printf("x6: %llx\n", regs->regs[6]);
    printf("x7: %llx\n", regs->regs[7]);
    printf("x8: %llx\n", regs->regs[8]);
    printf("x9: %llx\n", regs->regs[9]);
    printf("x10: %llx\n", regs->regs[10]);
    printf("x11: %llx\n", regs->regs[11]);
    printf("x12: %llx\n", regs->regs[12]);
    printf("x13: %llx\n", regs->regs[13]);
    printf("x14: %llx\n", regs->regs[14]);
    printf("x15: %llx\n", regs->regs[15]);
    printf("x16: %llx\n", regs->regs[16]);
    printf("x17: %llx\n", regs->regs[17]);
    printf("x18: %llx\n", regs->regs[18]);
    printf("x19: %llx\n", regs->regs[19]);
    printf("x20: %llx\n", regs->regs[20]);
    printf("x21: %llx\n", regs->regs[21]);
    printf("x22: %llx\n", regs->regs[22]);
    printf("x23: %llx\n", regs->regs[23]);
    printf("x24: %llx\n", regs->regs[24]);
    printf("x25: %llx\n", regs->regs[25]);
    printf("x26: %llx\n", regs->regs[26]);
    printf("x27: %llx\n", regs->regs[27]);
    printf("x28: %llx\n", regs->regs[28]);
    printf("fp: %llx\n", regs->regs[29]);
    printf("lr: %llx\n", regs->regs[30]);
    printf("sp: %llx\n", regs->sp);
    printf("pc: %llx\n", regs->pc);
    printf("pstate: %llx\n", regs->pstate);
}

void debug(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    printf("DBG: ");
    vprintf(fmt, args);
    va_end(args);
}

// Convert a hex file to a binary
void hex_to_bin(char *input_path) {
    FILE *input_file = fopen(input_path, "r");
    if (input_file == NULL) {
        printf("Error: could not open file %s\n", input_path);
        return;
    }
    uint32_t insn;
    while (fscanf(input_file, "0x%x\n", &insn) != EOF) {
        // for (int i=0; i<sizeof(insn); i++) {
        //     printf("%d ", ((char *)&insn)[i]);
        // }
        // printf("\n");
        for (int i=0; i<sizeof(insn); i++) {
            printf("%c", ((char *)&insn)[i]);
        }
    }
    fclose(input_file);
}
void bin_to_hex(char *input_path) {
    FILE *input_file = fopen(input_path, "r");
    if (input_file == NULL) {
        printf("Error: could not open file %s\n", input_path);
        return;
    }
    uint32_t insn;
    while (fread(&insn, sizeof(insn), 1, input_file) == 1) {
        printf("0x%08x\n", insn);
    }
    fclose(input_file);
}
void bin_to_asm(char *input_path) {
    FILE *input_file = fopen(input_path, "r");
    if (input_file == NULL) {
        printf("Error: could not open file %s\n", input_path);
        return;
    }
    uint32_t insn;
    char disas_str[0x1000];
    while (fread(&insn, sizeof(insn), 1, input_file) == 1) {
        libopcodes_disassemble(insn, disas_str, sizeof(disas_str));
        printf("%s\n", disas_str);
    }
    fclose(input_file);
}

extern int probe_idx;
void reproduce(char *input_path) {
    printf("Disassemble: \n");
    bin_to_asm(input_path);
    
    for (int i = 0; i < 32; i++) {
        probe_idx = i;
        int score = test_gadget(input_path, 1);
        debug("[%d] Score: %d\n", i, score);   
    }
}
int util_main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Util usage: cmd args...\n");
        return 1;
    }

    int cmd = atoi(argv[0]);
    
    switch(cmd) {
        case CMD_UTIL_HEX_TO_BIN: {
            if (argc < 2) {
                printf("hex to binary\n");
                printf("Usage: %d input_path\n", cmd);
                return 1;
            }
            char *input_path = argv[1];
            hex_to_bin(input_path);
            break;
        }
        case CMD_UTIL_BIN_TO_HEX: {
            if (argc < 2) {
                printf("binary to hex\n");
                printf("Usage: %d input_path\n", cmd);
                return 1;
            }
            char *input_path = argv[1];
            bin_to_hex(input_path);
            break;
        }
        case CMD_UTIL_BIN_TO_ASM: {
            if (argc < 2) {
                printf("binary to assembly\n");
                printf("Usage: %d input_path\n", cmd);
                return 1;
            }
            char *input_path = argv[1];
            bin_to_asm(input_path);
            break;
        }
        case CMD_UTIL_REPRO: {
            if (argc < 2) {
                printf("reproduce\n");
                printf("Usage: %d input_path\n", cmd);
                return 1;
            }
            char *input_path = argv[1];
            reproduce(input_path);
            break;
        }
        case CMD_UTIL_VERIFY: {
            printf("verify\n");
            if (argc < 2) {
                printf("Usage: %d input_path\n", cmd);
                return 1;
            }
            char *input_path = argv[1];

            FILE *file = fopen(input_path, "r");
            if (file == NULL) {
                fprintf(stderr, "Error opening file %s (%s)\n", input_path, strerror(errno));
                exit(1);
            }

            char src_code[GADGET_SIZE]= {0};
            size_t src_size = fread(src_code, 1, GADGET_SIZE, file);
            size_t src_code_size = src_size/sizeof(uint32_t);
            
            if (verify_gadget(src_code, src_code_size, 1) == -1) {
                printf("Gadget is invalid\n");
            } else {
                printf("Gadget is valid\n");
            }

            break;
        }
        default:
            printf("Error: unknown command %d\n", cmd);
            return 1;
    }

}
