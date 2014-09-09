/*
 * This file groups command line options definitions and associated
 * data that are common to both KLEE and Kleaver.
 */

#include "klee/CommandLine.h"

namespace klee {

llvm::cl::opt<bool>
UseFastCexSolver("use-fast-cex-solver",
		 llvm::cl::init(false),
		 llvm::cl::desc("(default=off)"));

llvm::cl::opt<bool>
UseCexCache("use-cex-cache",
            llvm::cl::init(true),
            llvm::cl::desc("Use counterexample caching (default=on)"));

llvm::cl::opt<bool>
UseCache("use-cache",
         llvm::cl::init(true),
         llvm::cl::desc("Use validity caching (default=on)"));

llvm::cl::opt<bool>
UseIndependentSolver("use-independent-solver",
                     llvm::cl::init(true),
                     llvm::cl::desc("Use constraint independence (default=on)"));

llvm::cl::opt<bool>
DebugValidateSolver("debug-validate-solver",
		             llvm::cl::init(false));
  

llvm::cl::opt<bool>
CoreSolverOptimizeDivides("solver-optimize-divides", 
                 llvm::cl::desc("Optimize constant divides into add/shift/multiplies before passing to core SMT solver (default=on)"),
                 llvm::cl::init(true));


/* Using cl::list<> instead of cl::bits<> results in quite a bit of ugliness when it comes to checking
 * if an option is set. Unfortunately with gcc4.7 cl::bits<> is broken with LLVM2.9 and I doubt everyone
 * wants to patch their copy of LLVM just for these options.
 */
//llvm::cl::list<QueryLoggingSolverType> queryLoggingOptions(
//    "use-query-log",
//    llvm::cl::desc("Log queries to a file. Multiple options can be specified seperate by a comma. By default nothing is logged."),
//    llvm::cl::values(
//        clEnumValN(ALL_PC,"all:pc","All queries in .pc (KQuery) format"),
//        clEnumValN(ALL_SMTLIB,"all:smt2","All queries in .smt2 (SMT-LIBv2) format"),
//        clEnumValN(SOLVER_PC,"solver:pc","All queries reaching the solver in .pc (KQuery) format"),
//        clEnumValN(SOLVER_SMTLIB,"solver:smt2","All queries reaching the solver in .smt2 (SMT-LIBv2) format"),
//        clEnumValEnd
//	),
//    llvm::cl::CommaSeparated
//);

#ifdef SUPPORT_METASMT

llvm::cl::opt<klee::MetaSMTBackendType>
UseMetaSMT("use-metasmt",
           llvm::cl::desc("Use MetaSMT as an underlying SMT solver and specify the solver backend type."),
           llvm::cl::values(clEnumValN(METASMT_BACKEND_NONE, "none", "Don't use metaSMT"),
                      clEnumValN(METASMT_BACKEND_STP, "stp", "Use metaSMT with STP"),
                      clEnumValN(METASMT_BACKEND_Z3, "z3", "Use metaSMT with Z3"),
                      clEnumValN(METASMT_BACKEND_BOOLECTOR, "btor", "Use metaSMT with Boolector"),
                      clEnumValEnd),  
           llvm::cl::init(METASMT_BACKEND_NONE));

#endif /* SUPPORT_METASMT */

}




