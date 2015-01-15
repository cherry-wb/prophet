//===-- PreProcessSolver.cpp -----------------------------------------------===//
//
//                     The KLEE Symbolic Virtual Machine
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#include "klee/Solver.h"

#include "klee/Expr.h"
#include "klee/SolverImpl.h"
#include "klee/Statistics.h"
#include "klee/util/ExprPPrinter.h"
#include "klee/Internal/Support/QueryLog.h"
#include "klee/Internal/System/Time.h"

#include "llvm/Support/CommandLine.h"
#include "llvm/Support/raw_os_ostream.h"

#include <fstream>

using namespace klee;
using namespace llvm;
using namespace klee::util;

///

class PreProcessSolver : public SolverImpl {
  Solver *solver;
  std::stringstream _os;
  ExprPPrinter *printer;

  void startQuery(const Query& query, const char *typeName,
                  const ref<Expr> *evalExprsBegin = 0,
                  const ref<Expr> *evalExprsEnd = 0,
                  const Array * const* evalArraysBegin = 0,
                  const Array * const* evalArraysEnd = 0) {
    std::stringstream os;
    llvm::raw_os_ostream ros(os);
    printer->printQuery(ros, query.constraints, query.expr,
                        evalExprsBegin, evalExprsEnd,
                        evalArraysBegin, evalArraysEnd);
    ros.flush();
  }

  void finishQuery(bool success) {
  }
  
public:
  PreProcessSolver(Solver *_solver)
  : solver(_solver),
    printer(ExprPPrinter::create(_os)) {
  }                                                      
  ~PreProcessSolver() {
    delete printer;
    delete solver;
  }
  
  bool computeTruth(const Query& query, bool &isValid) {
    startQuery(query, "Truth");
    bool success = solver->impl->computeTruth(query, isValid);
    finishQuery(success);
    return success;
  }

  bool computeValidity(const Query& query, Solver::Validity &result) {
    startQuery(query, "Validity");
    bool success = solver->impl->computeValidity(query, result);
    finishQuery(success);
    return success;
  }

  bool computeValue(const Query& query, ref<Expr> &result) {
    startQuery(query.withFalse(), "Value", 
               &query.expr, &query.expr + 1);
    bool success = solver->impl->computeValue(query, result);
    finishQuery(success);
    return success;
  }

  bool computeInitialValues(const Query& query,
                            const std::vector<const Array*> &objects,
                            std::vector< std::vector<unsigned char> > &values,
                            bool &hasSolution) {
    if (objects.empty()) {
      startQuery(query, "InitialValues",
                 0, 0);
    } else {
      startQuery(query, "InitialValues",
                 0, 0,
                 &objects[0], &objects[0] + objects.size());
    }
    bool success = solver->impl->computeInitialValues(query, objects, 
                                                      values, hasSolution);
    finishQuery(success);
    if (success) {
      if (hasSolution) {
        std::vector< std::vector<unsigned char> >::iterator
          values_it = values.begin();
        for (std::vector<const Array*>::const_iterator i = objects.begin(),
               e = objects.end(); i != e; ++i, ++values_it) {
        }
      }
    }
    return success;
  }
  SolverImpl::SolverRunStatus getOperationStatusCode() {
      return solver->impl->getOperationStatusCode();
  }

  char *getConstraintLog(const Query& query) {
    return solver->impl->getConstraintLog(query);
  }

  void setCoreSolverTimeout(double timeout) {
    solver->impl->setCoreSolverTimeout(timeout);
  }
};

///

Solver *klee::createPreProcessSolver(Solver *_solver) {
  return new Solver(new PreProcessSolver(_solver));
}
