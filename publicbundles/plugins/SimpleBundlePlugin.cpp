/*
 * SimpleBundlePlugin.cpp
 *
 *  Created on: 2014-5-25
 *      Author: wb
 */

#include "SimpleBundlePlugin.h"
#include <s2e/s2e_config.h>
#include <s2e/Plugins/CorePlugin.h>
#include <s2e/S2E.h>
#include <s2e/Plugin.h>
#include <s2e/s2e_qemu.h>
#include <s2e/S2EExecutionState.h>
#include <s2e/S2ESJLJ.h>
#include <s2e/Utils.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>

#include <algorithm>
#include <fstream>
#include <vector>

using namespace std;

namespace s2e {
S2E_DEFINE_PLUGIN(SimpleBundlePlugin, "S2E SimpleBundlePlugin functionality", "SimpleBundlePlugin",);

SimpleBundlePlugin::~SimpleBundlePlugin() {
}

void SimpleBundlePlugin::initialize() {
	s2e()->getDebugStream()<< "SimpleBundlePlugin::initialize" << "\n";
	s2e()->getCorePlugin()->onTranslateInstructionStart.connect(fsigc::mem_fun(*this, &SimpleBundlePlugin::slotTranslateInstructionStart));
	s2e()->getCorePlugin()->onTranslateInstructionEnd.connect(fsigc::mem_fun(*this, &SimpleBundlePlugin::slotTranslateInstructionEnd));
}
void SimpleBundlePlugin::slotTranslateInstructionStart(ExecutionSignal *signal,
                                                   S2EExecutionState *state,
                                                   TranslationBlock *tb,
                                                   uint64_t pc)
{
		s2e()->getDebugStream()<< "TranslateInstructionStart pc=" <<  pc << "\n";
		signal->connect(fsigc::mem_fun(*this,&SimpleBundlePlugin::onInstructionExecutionBefore));
}
void SimpleBundlePlugin::slotTranslateInstructionEnd(ExecutionSignal *signal,
                                                   S2EExecutionState *state,
                                                   TranslationBlock *tb,
                                                   uint64_t pc)
{
		s2e()->getDebugStream()<< "TranslateInstructionEnd pc=" << pc <<"\n";
		signal->connect(fsigc::mem_fun(*this,&SimpleBundlePlugin::onInstructionExecutionAfter));
}
void SimpleBundlePlugin::onInstructionExecutionBefore(S2EExecutionState* state, uint64_t pc){
	s2e()->getDebugStream()<< "ExecuteInstruction Before pc=" << hexval(pc)  <<"\n";
}
void SimpleBundlePlugin::onInstructionExecutionAfter(S2EExecutionState* state, uint64_t pc){
	s2e()->getDebugStream()<< "ExecuteInstruction After pc="<<  hexval(pc)  <<"\n";
}
} /* namespace s2e */
