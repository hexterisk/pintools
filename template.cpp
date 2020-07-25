/**
 * Template for a "PIN tool". Gets handles on a running process and outputs
 * diagnostic information about it.
 */
#include "pin.H"
#include <iostream>
#include <fstream>

// CLI Args ("knobs")
KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool"
	,"o"					// Argument name on CLI
	, "results.txt"			// Default value (can be blank)
	,"Name of output file"	// Description
);


// Usage info help message
INT32 Usage(){
	cerr << KNOB_BASE::StringKnobSummary() << endl;
	return -1;
}

// Print final diagnostic info after tracing completes
VOID Fini(INT32 code, VOID *v){
}


// SOME_TOOL main
int main(int argc, char *argv[]){
	// Pass own args to PIN_Init for handling, and on error print usage message
	if(PIN_Init(argc,argv)) return Usage();

	// Grab the output file name from args, and redirect output to it
	string fileName = KnobOutputFile.Value();
	out = new std::ofstream(fileName.c_str());

	// Register function to be called when the application exits
	PIN_AddFiniFunction(Fini, 0);

	// Start the program, never returns
	PIN_StartProgram();

	return 0;
}
