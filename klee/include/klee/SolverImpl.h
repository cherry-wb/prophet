//===-- SolverImpl.h --------------------------------------------*- C++ -*-===//
//
//                     The KLEE Symbolic Virtual Machine
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#ifndef KLEE_SOLVERIMPL_H
#define KLEE_SOLVERIMPL_H

#include <vector>
#include <map>
#include "klee/util/ExprEvaluator.h"
namespace klee {
  class Array;
  class ExecutionState;
  class Expr;
  class ExprEvaluator;
  struct Query;

  /// SolverImpl - Abstract base clase for solver implementations.
  class ReadEvaluator : public ExprEvaluator {
     protected:
       ref<Expr> getInitialValue(const Array &mo, unsigned index) {
       	if(mo.concreteBuffer.size()>0){
       		return klee::ConstantExpr::alloc(mo.concreteBuffer.at(index), Expr::Int8);
       	}else{
       		 return klee::ConstantExpr::alloc(0, Expr::Int8);
       	}
       }
     public:
       ReadEvaluator() {}
     };
  class SolverImpl {
    // DO NOT IMPLEMENT.
    SolverImpl(const SolverImpl&);
    void operator=(const SolverImpl&);
    
  public:
    SolverImpl() {readEvaluator = new ReadEvaluator;}
    virtual ~SolverImpl();

    enum SolverRunStatus { SOLVER_RUN_STATUS_SUCCESS_SOLVABLE,
                           SOLVER_RUN_STATUS_SUCCESS_UNSOLVABLE,
                           SOLVER_RUN_STATUS_FAILURE,
                           SOLVER_RUN_STATUS_TIMEOUT,
                           SOLVER_RUN_STATUS_FORK_FAILED,
                           SOLVER_RUN_STATUS_INTERRUPTED,
                           SOLVER_RUN_STATUS_UNEXPECTED_EXIT_CODE,
                           SOLVER_RUN_STATUS_WAITPID_FAILED };
    /// computeValidity - Compute a full validity result for the
    /// query.
    ///
    /// The query expression is guaranteed to be non-constant and have
    /// bool type.
    ///
    /// SolverImpl provides a default implementation which uses
    /// computeTruth. Clients should override this if a more efficient
    /// implementation is available.
    virtual bool computeValidity(const Query& query, Solver::Validity &result);
    
    /// computeTruth - Determine whether the given query is provable.
    ///
    /// The query expression is guaranteed to be non-constant and have
    /// bool type.
    virtual bool computeTruth(const Query& query, bool &isValid) = 0;

    /// computeValue - Compute a feasible value for the expression.
    ///
    /// The query expression is guaranteed to be non-constant.
    virtual bool computeValue(const Query& query, ref<Expr> &result) = 0;
    
    virtual bool computeInitialValues(const Query& query,
                                      const std::vector<const Array*> 
                                        &objects,
                                      std::vector< std::vector<unsigned char> > 
                                        &values,
                                      bool &hasSolution) = 0;  

    /// getOperationStatusCode - get the status of the last solver operation
    virtual SolverRunStatus getOperationStatusCode() = 0;

    /// getOperationStatusString - get string representation of the operation
    /// status code
    static const char* getOperationStatusString(SolverRunStatus statusCode);

    virtual char *getConstraintLog(const Query& query)  {
        // dummy
        return(NULL);
    }

    virtual void setCoreSolverTimeout(double timeout) {};
    ReadEvaluator* readEvaluator;
    void scanreadexpr(const ref<Expr> &e, std::map<const Array*,std::set<int> > &related);
};

}

#endif
