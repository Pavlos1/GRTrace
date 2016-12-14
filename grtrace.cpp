#include <stdio.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <fcntl.h>
#include <map>
#include <set>
#include "pin.H"

#define __MIN(a, b) ((a) < (b) ? (a) : (b))

enum SyscallRetHandler {
    DO_NOTHING,
    CHECK_IF_TARGET_FILE_OPENED,
    CHECK_IF_TARGET_FILE_CLOSED,
};

enum SyscallRetHandler handler = DO_NOTHING;
bool target_file_opened = false;
char * target_file;

ADDRINT target_fd;
std::map<ADDRINT, std::set<int> *> * taints
    = new std::map<ADDRINT, std::set<int> *>();
std::map<REG, std::set<int> *> * reg_taints
    = new std::map<REG, std::set<int> *>();

std::set<int> * operand_taints = new std::set<int>();

REG standardize_reg(REG reg) {
    return REG_FullRegName(reg);
}

char * getbasename(char * in) {
    char * out = (char *) malloc(255);
    int end=0;
    while ((in[end] != 0) && (end < 255)) end++;
    end--;
    
    int start=end;
    while ((in[start] != '/') && (start > 0)) start--;
    start++;

    int i;
    for (i=0; i <= end - start; i++) out[i] = in[i + start];
    out[i] = 0;

    return out;
}

VOID record_ins_call(VOID * ptr) {
    fprintf(stderr, "%p: CALL\n", ptr);
}

VOID record_ins_syscall_before(VOID * ins_ptr, ADDRINT number,
    ADDRINT arg0, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4,
        ADDRINT arg5) {
    switch (number) {
        case SYS_read:
            if (target_file_opened && (arg0 == target_fd)) {
                //fprintf(stderr, "Target file was read. Updating taints.\n");
                int curr = lseek(target_fd, 0, SEEK_CUR);
                int end = lseek(target_fd, 0, SEEK_END);
                lseek(target_fd, curr, SEEK_SET);

                for (int i=0; i < __MIN((int) arg2, end-curr); i++) {
                    if (taints->find(arg1 + i) == taints->end()) {
                        (*taints)[arg1 + i] = new std::set<int>(); 
                    }
                    if ((*taints)[arg1 + i] == NULL) {
                        (*taints)[arg1 + i] = new std::set<int>();
                    }

                    // We're overwriting, so remove previous taint
                    (*taints)[arg1 + i]->clear();
                    (*taints)[arg1 + i]->insert(curr + i);
                }
            }
            handler = DO_NOTHING;
            break;
        case SYS_write:
            if (target_file_opened && (arg0 == target_fd)) {
                fprintf(stderr, "Application tried to write to input file.\
                    Nope. Nope. Nope. Nope. Nope. Nope. Nope.\n");
                exit(1);
            }
            handler = DO_NOTHING;
            break;
        case SYS_open:
            if (strstr((char *) arg0, target_file)) {
                fprintf(stderr, "Trying to open what looks like our\
                    target file (%s)... ", (char *) arg0);
                handler = CHECK_IF_TARGET_FILE_OPENED;
            } else {
                handler = DO_NOTHING;
            }
            break;
        case SYS_close:
            if (target_file_opened && (arg0 == target_fd)) {
                fprintf(stderr, "Trying to close the target file... ");
                target_file_opened = false;
                handler = CHECK_IF_TARGET_FILE_CLOSED;
            } else {
                handler = DO_NOTHING;
            }
            break;
        default:
            handler = DO_NOTHING;
            break;
    }
}

VOID record_ins_syscall_after(VOID * ins_ptr, ADDRINT ret) {
    switch (handler) {
        case DO_NOTHING:
            break;

        case CHECK_IF_TARGET_FILE_OPENED:
            if ((long int) ret >= 0) {
                fprintf(stderr, "SUCCESS. (fd=%ld)\n", ret);
                target_file_opened = true;
                target_fd = ret;
            } else {
                fprintf(stderr, "failed.\n");
            }
            break;

        case CHECK_IF_TARGET_FILE_CLOSED:
            if (ret == 0) {
                fprintf(stderr, "SUCCESS.\n");
                target_file_opened = false;
            } else {
                fprintf(stderr, "failed. Will assume file is still open.\n");
            }
            break;
    }
}

VOID clear_operand_taints() {
    operand_taints->clear();
}

VOID record_ins_read(VOID * ins_ptr, CATEGORY category, OPCODE opcode,
    VOID * in_ptr) {
    if (taints->find((ADDRINT) in_ptr) != taints->end()) {
        if ((*taints)[(ADDRINT) in_ptr] != NULL) {
            for (auto offset : *((*taints)[(ADDRINT) in_ptr])) {
                operand_taints->insert(offset);
            }
        }
    }
}

VOID record_ins_reg_read(VOID * ins_ptr, CATEGORY category, OPCODE opcode,
    REG reg) {
    reg = standardize_reg(reg);

    // If instruction is PUSH/POP/CALL/RET, we don't want to propagate the RSP
    // taint, since E/RSP has no impact on the value pushed to the stack
    if(((category == XED_CATEGORY_PUSH) || (category == XED_CATEGORY_POP)
        || (category == XED_CATEGORY_CALL) || (category == XED_CATEGORY_RET))
            && (reg == REG_STACK_PTR)) return;

    // If the instruction is a conditional move, then due to us calling
    // INS_InsertPredicatedCall it will noy be instrumented unless the
    // condition was met. Hence, the taint in FLAGS should not be propagated.
    if ((category == XED_CATEGORY_CMOV) && (reg == REG_GFLAGS)) return;

    if (reg_taints->find(reg) != reg_taints->end()) {
        if ((*reg_taints)[reg] != NULL) {
            for (auto offset : *((*reg_taints)[reg])) {
                operand_taints->insert(offset);
            }
        }
    }
}

VOID record_ins_write(VOID * ins_ptr, CATEGORY category, OPCODE opcode,
    VOID * out_ptr) {
    if (taints->find((ADDRINT) out_ptr) == taints->end()) {
        (*taints)[(ADDRINT) out_ptr] = new std::set<int>();
    }
    if ((*taints)[(ADDRINT) out_ptr] == NULL) {
        (*taints)[(ADDRINT) out_ptr] = new std::set<int>();
    }

    // TODO: A better way of doing this
    if (operand_taints->empty()) {
        delete (*taints)[(ADDRINT) out_ptr];
        taints->erase((ADDRINT) out_ptr);
        return;
    }

    //fprintf(stderr, "Clearing taints for %p\n", out_ptr);
    (*taints)[(ADDRINT) out_ptr]->clear();

    for (auto offset : *operand_taints) {
        //fprintf(stderr, "Tainting %p with %d\n", out_ptr, offset);
        (*taints)[(ADDRINT) out_ptr]->insert(offset);
    }
}

VOID record_ins_reg_write(VOID * ins_ptr, CATEGORY category,
    OPCODE opcode, REG reg) {
    reg = standardize_reg(reg);

    // If the instruction is PUSH/POP/CALL/RET, we do not want to modify
    // the taint of E/RSP in any way, since its being decremented
    // by a known quatity.
    if(((category == XED_CATEGORY_PUSH) || (category == XED_CATEGORY_POP)
        || (category == XED_CATEGORY_CALL) || (category == XED_CATEGORY_RET))
            && (reg == REG_STACK_PTR)) return;

    if (reg_taints->find(reg) == reg_taints->end()) {
        (*reg_taints)[reg] = new std::set<int>();
    }
    if ((*reg_taints)[reg] == NULL) {
        (*reg_taints)[reg] = new std::set<int>();
    }

    // TODO: A better way of doing this. 
    if (operand_taints->empty()) {
        delete (*reg_taints)[reg];
        reg_taints->erase(reg);
        return;
    }

    (*reg_taints)[reg]->clear();

    for (auto offset : *operand_taints) {
        (*reg_taints)[reg]->insert(offset);
    }
}

VOID SyscallEntry(THREADID threadIndex, CONTEXT *ctxt, SYSCALL_STANDARD std,
    VOID *v) {
    record_ins_syscall_before((VOID *) PIN_GetContextReg(ctxt, REG_INST_PTR),
        PIN_GetSyscallNumber(ctxt, std),
        PIN_GetSyscallArgument(ctxt, std, 0),
        PIN_GetSyscallArgument(ctxt, std, 1),
        PIN_GetSyscallArgument(ctxt, std, 2),
        PIN_GetSyscallArgument(ctxt, std, 3),
        PIN_GetSyscallArgument(ctxt, std, 4),
        PIN_GetSyscallArgument(ctxt, std, 5));
}

VOID SyscallExit(THREADID threadIndex, CONTEXT *ctxt, SYSCALL_STANDARD std,
    VOID *v) {
    record_ins_syscall_after((VOID *) PIN_GetContextReg(ctxt, REG_INST_PTR),
        PIN_GetSyscallReturn(ctxt, std));
}

VOID Instruction(INS ins, VOID * v) {
    // Handle SYSCALL/0x80 interrupt to check for I/O taints originating
    // from the target file
    if (INS_IsSyscall(ins) && INS_HasFallThrough(ins)) {
        // Executed before control is handed over to the kernel
        INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
            (AFUNPTR) record_ins_syscall_before, IARG_INST_PTR,
            IARG_SYSCALL_NUMBER, IARG_SYSARG_VALUE, 0, IARG_SYSARG_VALUE, 1,
            IARG_SYSARG_VALUE, 2, IARG_SYSARG_VALUE, 3, IARG_SYSARG_VALUE, 4,
            IARG_SYSARG_VALUE, 5, IARG_END);
        // Executed after kernel returns
        INS_InsertPredicatedCall(ins, IPOINT_AFTER,
            (AFUNPTR) record_ins_syscall_after, IARG_INST_PTR,
            IARG_SYSRET_VALUE, IARG_END);

    } else {
        // Handle memory I/O to check for taint propogation
        //
        // NOTE: The order of the for loops is important;
        // record_ins(_reg)_write will clear its own taints,
        // so all record_ins(_reg)_read methods must be called
        // first to avoid losing information
        UINT32 memOperands = INS_MemoryOperandCount(ins);
        UINT32 regROperands = INS_MaxNumRRegs(ins);
        UINT32 regWOperands = INS_MaxNumWRegs(ins);

        // Clear taints for current instruction
        INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
            (AFUNPTR) clear_operand_taints, IARG_END);

        // Populate operand_taints with taints from read memory
        for (UINT32 memOp = 0; memOp < memOperands; memOp++) {
            if (INS_MemoryOperandIsRead(ins, memOp)) {
                INS_InsertPredicatedCall(
                    ins, IPOINT_BEFORE, (AFUNPTR) record_ins_read,
                    IARG_INST_PTR, IARG_UINT32, INS_Category(ins),
                    IARG_UINT32, INS_Opcode(ins),
                    IARG_MEMORYOP_EA, memOp,
                    IARG_END);
            }
        }

        // Populate operand_taints with taints from read registers
        for (UINT32 regOp = 0; regOp < regROperands; regOp++) {
            INS_InsertPredicatedCall(
                ins, IPOINT_BEFORE, (AFUNPTR) record_ins_reg_read,
                IARG_INST_PTR, IARG_UINT32, INS_Category(ins),
                IARG_UINT32, INS_Opcode(ins), 
                IARG_UINT32, INS_RegR(ins, regOp),
                IARG_END);
        }

        // Propagate taints in operand_taints to written memory
        for (UINT32 memOp = 0; memOp < memOperands; memOp++) {        
            if (INS_MemoryOperandIsWritten(ins, memOp)) {
                INS_InsertPredicatedCall(
                    ins, IPOINT_BEFORE, (AFUNPTR) record_ins_write,
                    IARG_INST_PTR, IARG_UINT32, INS_Category(ins),
                    IARG_UINT32, INS_Opcode(ins),
                    IARG_MEMORYOP_EA, memOp,
                    IARG_END);
            }
        }

        // Propagate taints in operand_taints to written registers
        for (UINT32 regOp = 0; regOp < regWOperands; regOp++) {
            INS_InsertPredicatedCall(
                ins, IPOINT_BEFORE, (AFUNPTR) record_ins_reg_write,
                IARG_INST_PTR, IARG_UINT32, INS_Category(ins),
                IARG_UINT32, INS_Opcode(ins), 
                IARG_UINT32, INS_RegW(ins, regOp),
                IARG_END);
        }
    }
}

VOID Fini(INT32 code, VOID * v) {
    fprintf(stderr, "Writing taints to file... ");
    FILE * fp = fopen("taints.txt", "w");
    for (auto iterator = reg_taints->begin(); iterator != reg_taints->end();
        iterator++) {
        fprintf(fp, "%s: ", REG_StringShort(iterator->first).c_str());
        for (auto offset : *(iterator->second)) {
            fprintf(fp, "%d, ", offset);
        }
        fprintf(fp, "\n");
    }
    for (auto iterator = taints->begin(); iterator != taints->end();
        iterator++) {
        fprintf(fp, "%lx: ", iterator->first);
        for (auto offset : *(iterator->second)) {
            fprintf(fp, "%d, ", offset);
        }
        fprintf(fp, "\n");
    }
    fclose(fp);
    fprintf(stderr, "done.\n");

    delete operand_taints;
    for (auto iterator = taints->begin(); iterator != taints->end();
        iterator++) {
        delete iterator->second;
    }
    delete taints;

    for (auto iterator = reg_taints->begin(); iterator != reg_taints->end();
        iterator++) {
        delete iterator->second;
    }
    delete reg_taints;
}

int main(int argc, char ** argv) {
    // Last argument should be filename
    target_file = getbasename(argv[argc - 1]);

    if (PIN_Init(argc, argv)) {
        fprintf(stderr, "PIN initialization failed\n");
        exit(1);
    }

    INS_AddInstrumentFunction(Instruction, 0);
    PIN_AddSyscallEntryFunction(SyscallEntry, 0);
    PIN_AddSyscallExitFunction(SyscallExit, 0);

    PIN_AddFiniFunction(Fini, 0);

    PIN_StartProgram();

    return 0;
}

