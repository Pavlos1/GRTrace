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
    MMAP,
};

enum SyscallRetHandler handler = DO_NOTHING;
bool target_file_opened = false;
char * target_file;
ADDRINT mmap_args[6];
FILE * fp;

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

void write_taints() {
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

    fprintf(fp, "-------------------------------------------------\n");
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

                    write_taints();
                }
            }
            handler = DO_NOTHING;
            break;
        case SYS_write:
            if (target_file_opened && (arg0 == target_fd)) {
                fprintf(stderr, "Application tried to write to input file."
                    " Nope. Nope. Nope. Nope. Nope. Nope. Nope.\n");
                exit(1);
            }
            handler = DO_NOTHING;
            break;
        case SYS_open:
            if (strstr((char *) arg0, target_file)) {
                fprintf(stderr, "Trying to open what looks like our"
                    " target file (%s)... ", (char *) arg0);
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
        case SYS_mmap:
            if (target_file_opened && (arg4 == target_fd)) {
                mmap_args[0] = arg0;
                mmap_args[1] = arg1;
                mmap_args[2] = arg2;
                mmap_args[3] = arg3;
                mmap_args[4] = arg4;
                mmap_args[5] = arg5;
                handler = MMAP;
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

        case MMAP:
            if (ret != 0) {
                int curr_pos = lseek(target_fd, 0, SEEK_CUR);
                int file_len = lseek(target_fd, 0, SEEK_END);
                lseek(target_fd, curr_pos, SEEK_SET);

                int length = mmap_args[1];
                for (int delta = 0; delta < length; delta++) {
                    int offset = mmap_args[5] + delta;
                    ADDRINT mem = ret + delta;
                    if (offset < file_len) {
                        if ((taints->find(mem) == taints->end())
                            || ((*taints)[mem] == NULL)) {
                            (*taints)[mem] = new std::set<int>();
                        } else {
                            (*taints)[mem]->clear();
                        }

                        (*taints)[mem]->insert(offset);
                    }
                }
            }
            break;
    }
}

VOID clear_operand_taints(VOID * ins_ptr) {
    operand_taints->clear();
}

VOID clear_reg_taint(VOID * ins_ptr, REG reg) {
    reg = standardize_reg(reg);

    if (reg_taints->find(reg) != reg_taints->end()) {
        if ((*reg_taints)[reg] != NULL) {
            delete (*reg_taints)[reg];
        }

        reg_taints->erase(reg);
    }
}

VOID record_ins_read(VOID * ins_ptr, CATEGORY category, OPCODE opcode,
    char * in_ptr, UINT32 length) {
    for (UINT32 i=0; i<length; i++) {
        if (taints->find((ADDRINT) (in_ptr+i)) != taints->end()) {
            if ((*taints)[(ADDRINT) (in_ptr+i)] != NULL) {
                for (auto offset : *((*taints)[(ADDRINT) (in_ptr+i)])) {
                    operand_taints->insert(offset);
                }
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

    // If the instruction is a conditional instruction, then due to us calling
    // INS_InsertPredicatedCall it will not be instrumented unless the
    // condition was met. Hence, the taint in FLAGS should not be propagated.
    // Conditional jumps are excepted since we want to know about branches.
    if ((category != XED_CATEGORY_COND_BR) && (reg == REG_GFLAGS)) return;

    // I don't really have a proper justification for this, other than that
    // the assembly trace does a lot of MOV/LEA on memory that is specified
    // relative to (%rip)
    if (reg == REG_INST_PTR) return;

    if (reg_taints->find(reg) != reg_taints->end()) {
        if ((*reg_taints)[reg] != NULL) {
            for (auto offset : *((*reg_taints)[reg])) {
                operand_taints->insert(offset);
            }
        }
    }
}

VOID record_ins_write(VOID * ins_ptr, CATEGORY category, OPCODE opcode,
    char * out_ptr, UINT32 length) {
    for (UINT32 i=0; i<length; i++) {
        if (taints->find((ADDRINT) (out_ptr+i)) == taints->end()) {
            (*taints)[(ADDRINT) (out_ptr+i)] = new std::set<int>();
        }
        if ((*taints)[(ADDRINT) (out_ptr+i)] == NULL) {
            (*taints)[(ADDRINT) (out_ptr+i)] = new std::set<int>();
        }

        // TODO: A better way of doing this
        if (operand_taints->empty()) {
            delete (*taints)[(ADDRINT) (out_ptr+i)];
            taints->erase((ADDRINT) (out_ptr+i));
            return;
        }

        (*taints)[(ADDRINT) (out_ptr+i)]->clear();

        for (auto offset : *operand_taints) {
            (*taints)[(ADDRINT) (out_ptr+i)]->insert(offset);
        }
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

VOID record_ins_xchg_reg_reg(VOID * ins_ptr, REG reg1, REG reg2) {
    reg1 = standardize_reg(reg1);
    reg2 = standardize_reg(reg2);

    if (reg_taints->find(reg1) == reg_taints->end()) {
        if (reg_taints->find(reg2) != reg_taints->end()) {
            (*reg_taints)[reg1] = (*reg_taints)[reg2];
        }
        reg_taints->erase(reg2);
    } else {
        std::set<int> * tmp = (*reg_taints)[reg1];
        if (reg_taints->find(reg2) == reg_taints->end()) {
            reg_taints->erase(reg1);
        } else {
            (*reg_taints)[reg1] = (*reg_taints)[reg2];
        }
        (*reg_taints)[reg2] = tmp;
    }
}

VOID record_ins_xchg_reg_mem(VOID * ins_ptr, REG reg, VOID * mem, UINT32 size) {
    reg = standardize_reg(reg);

    if (reg_taints->find(reg) == reg_taints->end() ||
        (*reg_taints)[reg] == NULL) {
        (*reg_taints)[reg] = new std::set<int>;
        for (ADDRINT _mem = (ADDRINT) mem;
            _mem < (ADDRINT) mem + size; _mem++) {
            if ((taints->find(_mem) != taints->end())
                && ((*taints)[_mem] != NULL)) {
                for (auto offset : *((*taints)[_mem]))
                    (*reg_taints)[reg]->insert(offset);
            }
            taints->erase(_mem);
        }
    } else {
        std::set<int> * tmp = new std::set<int>();
        for (auto offset : *((*reg_taints)[reg])) tmp->insert(offset);
        (*reg_taints)[reg]->clear();
        for (ADDRINT _mem = (ADDRINT) mem;
            _mem < (ADDRINT) mem + size; _mem++) {
            if (taints->find(_mem) != taints->end()
                && ((*taints)[_mem] != NULL)) {
                for (auto offset : *((*taints)[_mem]))
                    (*reg_taints)[reg]->insert(offset);
            }
            (*taints)[_mem] = new std::set<int>();
            for (auto offset : *tmp) (*taints)[_mem]->insert(offset);
        }
        delete tmp;
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

    // Specifically handle the case of `XOR %REG, %REG` and `SUB %REG, %REG`
    // Both %REG(=0) and %RFLAGS are now deterministic, and thus not tainted
    } else if (((INS_Opcode(ins) == XED_ICLASS_XOR)
        || (INS_Opcode(ins) == XED_ICLASS_SUB))
            && INS_OperandIsReg(ins, 0) && INS_OperandIsReg(ins, 1)
                && (INS_OperandReg(ins, 0) == INS_OperandReg(ins, 1))) {

                INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                    (AFUNPTR) clear_reg_taint, IARG_INST_PTR,
                    IARG_UINT32, INS_OperandReg(ins, 0), IARG_END);
                INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                    (AFUNPTR) clear_reg_taint, IARG_INST_PTR,
                    IARG_UINT32, REG_GFLAGS, IARG_END);

    // TODO: CMPXCHG? (XADD should hypothetically function as normal)
    } else if (INS_Opcode(ins) == XED_ICLASS_XCHG) {

        if (INS_OperandIsReg(ins, 0) && INS_OperandIsReg(ins, 1)) {
            INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                (AFUNPTR) record_ins_xchg_reg_reg, IARG_INST_PTR,
                IARG_UINT32, INS_OperandReg(ins, 0),
                IARG_UINT32, INS_OperandReg(ins, 1), IARG_END);

        } else {
            // This should work with both (REG, MEM) and (MEM, REG)
            INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                (AFUNPTR) record_ins_xchg_reg_mem, IARG_INST_PTR,
                IARG_UINT32, INS_OperandReg(ins, 0),
                IARG_MEMORYOP_EA, 0,
                IARG_UINT32, INS_MemoryOperandSize(ins, 0), IARG_END);
        }
    
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
            (AFUNPTR) clear_operand_taints, IARG_INST_PTR, IARG_END);

        // Populate operand_taints with taints from read memory
        for (UINT32 memOp = 0; memOp < memOperands; memOp++) {
            if (INS_MemoryOperandIsRead(ins, memOp)) {
                INS_InsertPredicatedCall(
                    ins, IPOINT_BEFORE, (AFUNPTR) record_ins_read,
                    IARG_INST_PTR, IARG_UINT32, INS_Category(ins),
                    IARG_UINT32, INS_Opcode(ins),
                    IARG_MEMORYOP_EA, memOp,
                    IARG_UINT32, INS_MemoryOperandSize(ins, memOp),
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
                    IARG_UINT32, INS_MemoryOperandSize(ins, memOp),
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
    write_taints();
    fclose(fp);

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
    // Open taints file for writing
    fp = fopen("taints.txt", "w");

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

