#include "pin.H"
#include <iostream>
#include <fstream>

// Instruments the loaded image.
VOID Image(IMG img, VOID *v) {
    std::cout << IMG_Name(img) << std::endl;
    for (SEC sec = IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec)) {
        std::cout << "\t=> " << SEC_Name(sec) << std::endl;
        for (RTN rtn = SEC_RtnHead(sec); RTN_Valid(rtn); rtn = RTN_Next(rtn)) {
            std::cout << "\t\t=> " << RTN_Name(rtn) << std::endl;
        }
    }
}

INT32 Usage() {
    std::cerr << "Prints all the imports in a hierarchial manner." << std::endl;
    return -1;
}

int main(int argc, char *argv[])
{
    // Initialize pin & symbol manager.
    PIN_InitSymbols();

    if( PIN_Init(argc,argv) ) {
        return Usage();
    }

    // Register Image to be called to instrument functions.
    IMG_AddInstrumentFunction(Image, 0);

    // Never returns.
    PIN_StartProgram();

    return 0;
}