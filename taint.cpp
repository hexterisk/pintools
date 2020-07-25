#include "pin.H"

#include <list>
#include <fstream>
#include <iostream>
#include <asm/unistd.h>

// Global variables.
static unsigned int skipOpen;
std::list<REG> registerTainted;
std::list<UINT64> addressTainted;

// Define macros.
#define SKIP(){ if(skipOpen++ == 0) return; }


/*******************************************************************************************************************\
|                                                  TAINT FUNCTIONS                                                  |
\*******************************************************************************************************************/


// Check if the register is already tainted.
bool checkAlreadyRegTainted(REG reg) {
    std::list<REG>::iterator i;

    for(i = registerTainted.begin(); i != registerTainted.end(); i++) {
        if (*i == reg) {
            return true;
        }
    }
    return false;
}

// Removes taint from a memory address.
VOID removeMemTainted(UINT64 addr) {
    addressTainted.remove(addr);
    std::cout << std::hex << "\t\t\t" << addr << " is now freed" << std::endl;
}

// Adds taint to a memory address.
VOID addMemTainted(UINT64 addr) {
    addressTainted.push_back(addr);
    std::cout << std::hex << "\t\t\t" << addr << " is now tainted" << std::endl;
}

// Add taint to a register.
bool taintReg(REG reg) {

    // Check if the register is already tainted.
    if (checkAlreadyRegTainted(reg) == true){
        std::cout << "\t\t\t" << REG_StringShort(reg) << " is already tainted." << std::endl;
        return false;
    }

    // Switch case designed with fall throughs for smaller register making up a bigger one.
    // If a larger register is tainted, it's smaller parts get tainted too.
    switch(reg){

        case REG_RAX:  registerTainted.push_front(REG_RAX);
        case REG_EAX:  registerTainted.push_front(REG_EAX); 
        case REG_AX:   registerTainted.push_front(REG_AX); 
        case REG_AH:   registerTainted.push_front(REG_AH); 
        case REG_AL:   registerTainted.push_front(REG_AL); 
            break;

        case REG_RBX:  registerTainted.push_front(REG_RBX);
        case REG_EBX:  registerTainted.push_front(REG_EBX);
        case REG_BX:   registerTainted.push_front(REG_BX);
        case REG_BH:   registerTainted.push_front(REG_BH);
        case REG_BL:   registerTainted.push_front(REG_BL);
            break;

        case REG_RCX:  registerTainted.push_front(REG_RCX); 
        case REG_ECX:  registerTainted.push_front(REG_ECX);
        case REG_CX:   registerTainted.push_front(REG_CX);
        case REG_CH:   registerTainted.push_front(REG_CH);
        case REG_CL:   registerTainted.push_front(REG_CL);
            break;

        case REG_RDX:  registerTainted.push_front(REG_RDX); 
        case REG_EDX:  registerTainted.push_front(REG_EDX); 
        case REG_DX:   registerTainted.push_front(REG_DX); 
        case REG_DH:   registerTainted.push_front(REG_DH); 
        case REG_DL:   registerTainted.push_front(REG_DL); 
            break;

        case REG_RDI:  registerTainted.push_front(REG_RDI); 
        case REG_EDI:  registerTainted.push_front(REG_EDI); 
        case REG_DI:   registerTainted.push_front(REG_DI); 
        case REG_DIL:  registerTainted.push_front(REG_DIL); 
            break;

        case REG_RSI:  registerTainted.push_front(REG_RSI); 
        case REG_ESI:  registerTainted.push_front(REG_ESI); 
        case REG_SI:   registerTainted.push_front(REG_SI); 
        case REG_SIL:  registerTainted.push_front(REG_SIL); 
            break;

        default:
        std::cout << "\t\t\t" << REG_StringShort(reg) << " can't be tainted" << std::endl;
        return false;
    }
    std::cout << "\t\t\t" << REG_StringShort(reg) << " is now tainted" << std::endl;
    return true;
}

// Remove taint from a register.
bool removeRegTainted(REG reg) {
  
    // Switch case designed with fall throughs for smaller register making up a bigger one.
    // If a larger register is freed, it's smaller parts are freed too.
    switch(reg){

        case REG_RAX:  registerTainted.remove(REG_RAX);
        case REG_EAX:  registerTainted.remove(REG_EAX);
        case REG_AX:   registerTainted.remove(REG_AX);
        case REG_AH:   registerTainted.remove(REG_AH);
        case REG_AL:   registerTainted.remove(REG_AL);
            break;

        case REG_RBX:  registerTainted.remove(REG_RBX);
        case REG_EBX:  registerTainted.remove(REG_EBX);
        case REG_BX:   registerTainted.remove(REG_BX);
        case REG_BH:   registerTainted.remove(REG_BH);
        case REG_BL:   registerTainted.remove(REG_BL);
            break;

        case REG_RCX:  registerTainted.remove(REG_RCX); 
        case REG_ECX:  registerTainted.remove(REG_ECX);
        case REG_CX:   registerTainted.remove(REG_CX);
        case REG_CH:   registerTainted.remove(REG_CH);
        case REG_CL:   registerTainted.remove(REG_CL);
            break;

        case REG_RDX:  registerTainted.remove(REG_RDX); 
        case REG_EDX:  registerTainted.remove(REG_EDX); 
        case REG_DX:   registerTainted.remove(REG_DX); 
        case REG_DH:   registerTainted.remove(REG_DH); 
        case REG_DL:   registerTainted.remove(REG_DL); 
            break;

        case REG_RDI:  registerTainted.remove(REG_RDI); 
        case REG_EDI:  registerTainted.remove(REG_EDI); 
        case REG_DI:   registerTainted.remove(REG_DI); 
        case REG_DIL:  registerTainted.remove(REG_DIL); 
            break;

        case REG_RSI:  registerTainted.remove(REG_RSI); 
        case REG_ESI:  registerTainted.remove(REG_ESI); 
        case REG_SI:   registerTainted.remove(REG_SI); 
        case REG_SIL:  registerTainted.remove(REG_SIL); 
            break;

        default:
        return false;
    }
    std::cout << "\t\t\t" << REG_StringShort(reg) << " has been freed." << std::endl;
    return true;
}

VOID ReadMem(UINT64 insAddr, std::string insDis, UINT32 opCount, REG reg_r, UINT64 memOp) {
    
    std::list<UINT64>::iterator i;
    UINT64 addr = memOp;
    
    // If operands are not two, data isn't being written to memory.
    if (opCount != 2)
        return;
    
    // Iterate through tainted address to find the current one.
    // If the matched tainted address is read by an untainted register, add the taint to this register.
    for(i = addressTainted.begin(); i != addressTainted.end(); i++){
        if (addr == *i){
            std::cout << std::hex << "[READ in " << addr << "]\t" << insAddr << ": " << insDis << std::endl;
            taintReg(reg_r);
            return ;
        }
    }

    // If register is tainted and the memory it reads from isn't, remove the taint from this register.
    if (checkAlreadyRegTainted(reg_r)){
        std::cout << std::hex << "[READ in " << addr << "]\t" << insAddr << ": " << insDis << std::endl;
        removeRegTainted(reg_r);
    }
}

VOID WriteMem(UINT64 insAddr, std::string insDis, UINT32 opCount, REG reg_r, UINT64 memOp)
{
    std::list<UINT64>::iterator i;
    UINT64 addr = memOp;

    // If operands are not two, data isn't being written to memory.
    if (opCount != 2)
        return;

    // Iterate through tainted address to find the current one.
    // If the matched tainted address is overwritten by an untainted register, remove the taint from this memory address.
    for(i = addressTainted.begin(); i != addressTainted.end(); i++) {
        if (addr == *i){
            std::cout << std::hex << "[WRITE in " << addr << "]\t" << insAddr << ": " << insDis << std::endl;
            if (!REG_valid(reg_r) || !checkAlreadyRegTainted(reg_r))
                removeMemTainted(addr);
            return ;
        }
    }

    // If register is tainted, the memory it writes to gets tainted.
    if (checkAlreadyRegTainted(reg_r)) {
        std::cout << std::hex << "[WRITE in " << addr << "]\t" << insAddr << ": " << insDis << std::endl;
        addMemTainted(addr);
    }
}

// Taint the register.
VOID taintRegister(UINT64 insAddr, std::string insDis, UINT32 opCount, REG reg_r, REG reg_w) {
    
    // If operands are not two, data isn't being moved between operands.
    if (opCount != 2)
        return;

    // Ensure the register is valid. INS_RegR can return 'Invalid()'.
    if (REG_valid(reg_w)) {
        if (checkAlreadyRegTainted(reg_w) && (!REG_valid(reg_r) || !checkAlreadyRegTainted(reg_r))) {
        std::cout << "[SPREAD]\t\t" << insAddr << ": " << insDis << std::endl;
        std::cout << "\t\t\toutput: "<< REG_StringShort(reg_w) << " | input: " << (REG_valid(reg_r) ? REG_StringShort(reg_r) : "constant") << std::endl;
        removeRegTainted(reg_w);
        }
        else if (!checkAlreadyRegTainted(reg_w) && checkAlreadyRegTainted(reg_r)) {
        std::cout << "[SPREAD]\t\t" << insAddr << ": " << insDis << std::endl;
        std::cout << "\t\t\toutput: " << REG_StringShort(reg_w) << " | input: "<< REG_StringShort(reg_r) << std::endl;
        taintReg(reg_w);
        }
    }
}

// Check if register involved is tainted.
VOID trackData(UINT64 insAddr, std::string insDis, REG reg) {

    // Ensure the register is valid. INS_RegR can return 'Invalid()'.
    if (!REG_valid(reg))
        return;

    // If register being used in the operation is tainted, track it.
    if (checkAlreadyRegTainted(reg)) {
        std::cout << "[FOLLOW]\t\t" << insAddr << ": " << insDis << std::endl;
    }
}


/*******************************************************************************************************************\
|                                             INSTRUMENTATION FUNCTIONS                                             |
\*******************************************************************************************************************/


// Instruments all the instructions.
VOID instrumentInstructions(INS ins, VOID *v) {

    // For read instructions.
    if (INS_OperandCount(ins) > 1 && INS_MemoryOperandIsRead(ins, 0) && INS_OperandIsReg(ins, 0)){
        INS_InsertCall(
            ins, IPOINT_BEFORE, (AFUNPTR)ReadMem,
            IARG_ADDRINT, INS_Address(ins),
            IARG_PTR, new std::string(INS_Disassemble(ins)),
            IARG_UINT32, INS_OperandCount(ins),             // number of operands in this instruction.
            IARG_UINT32, INS_OperandReg(ins, 0),
            IARG_MEMORYOP_EA, 0,
            IARG_END);
    }
    // For write instructions.
    else if (INS_OperandCount(ins) > 1 && INS_MemoryOperandIsWritten(ins, 0)){
        INS_InsertCall(
            ins, IPOINT_BEFORE, (AFUNPTR)WriteMem,
            IARG_ADDRINT, INS_Address(ins),
            IARG_PTR, new std::string(INS_Disassemble(ins)),
            IARG_UINT32, INS_OperandCount(ins),             // number of operands in this instruction.
            IARG_UINT32, INS_OperandReg(ins, 1),
            IARG_MEMORYOP_EA, 0,
            IARG_END);
    }
    // To taint the register between read and write.
    else if (INS_OperandCount(ins) > 1 && INS_OperandIsReg(ins, 0)){
        INS_InsertCall(
            ins, IPOINT_BEFORE, (AFUNPTR)taintRegister,
            IARG_ADDRINT, INS_Address(ins),
            IARG_PTR, new std::string(INS_Disassemble(ins)),
            IARG_UINT32, INS_OperandCount(ins),             // number of operands in this instruction.
            IARG_UINT32, INS_RegR(ins, 0),                  // first read register of this instruction.
            IARG_UINT32, INS_RegW(ins, 0),                  // first write register of this instruction.
            IARG_END);
    }
    // To track the data through memory and check if register reading the value is already tainted.
    if (INS_OperandCount(ins) > 1 && INS_OperandIsReg(ins, 0)){
        INS_InsertCall(
            ins, IPOINT_BEFORE, (AFUNPTR)trackData,
            IARG_ADDRINT, INS_Address(ins),
            IARG_PTR, new std::string(INS_Disassemble(ins)),
            IARG_UINT32, INS_RegR(ins, 0),                  // first read register of this instruction.
            IARG_END);
    }
}

// Instruments all the syscalls at entry.
VOID instrumentSyscallEntry(THREADID thread_id, CONTEXT *ctx, SYSCALL_STANDARD std, void *v)
{
  unsigned int i;
  UINT64 buf, count;

    // Check if a read is being performed.
    if (PIN_GetSyscallNumber(ctx, std) == __NR_read) {

        // Skips the first call.
        // Refer https://stackoverflow.com/questions/14093952/pin-tool-for-tracking-createfile-calls/15179667#15179667 for a brief on two implicit calls.
        SKIP();

        // Fetch the arguments passed to the read syscall: ssize_t read(int fd, void *buf, size_t count);
        buf = static_cast<UINT64>((PIN_GetSyscallArgument(ctx, std, 1)));
        count  = static_cast<UINT64>((PIN_GetSyscallArgument(ctx, std, 2)));

        for (i = 0; i < count; i++)
        addressTainted.push_back(buf+i);
        
        std::cout << "[TAINT](syscall: read)\t\tbytes tainted from " << std::hex << "0x" << buf << " to 0x" << buf+count << std::endl;
    }
}


/*******************************************************************************************************************\
|                                                     INTERFACE                                                     |
\*******************************************************************************************************************/


// Define usage of the tool.
INT32 Usage() {
    std::cerr << "Follow your data through registers and memory." << std::endl;
    return -1;
}

int main(int argc, char *argv[]) {

    // Initialize pin and symbol manager.
    PIN_InitSymbols();
    if (PIN_Init(argc,argv)) {
        return Usage();
    }

    // Set flavour as Intel.
    PIN_SetSyntaxIntel();

    // Instrument syscalls.
    PIN_AddSyscallEntryFunction(instrumentSyscallEntry, 0);

    // Instrument instructions.
    INS_AddInstrumentFunction(instrumentInstructions, 0);
    
    // Never returns
    PIN_StartProgram();

    return 0;
}