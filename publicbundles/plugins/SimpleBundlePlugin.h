/*
 * SimpleBundlePlugin.h
 *
 *  Created on: 2014-5-25
 *      Author: wb
 */

#ifndef SIMPLE_BUNDLEPLUGIN_H_
#define SIMPLE_BUNDLEPLUGIN_H_
#include <limits.h>
#include <stdint.h>
#include <s2e/Plugin.h>
#include <s2e/Plugins/CorePlugin.h>
#include <s2e/Signals/Signals.h>
#include <s2e/S2EExecutionState.h>
#include <s2e/Plugins/BaseInstructions.h>
namespace s2e {
 class S2EExecutionState;
class SimpleBundlePlugin : public Plugin {
	S2E_PLUGIN

	private:
public:
	SimpleBundlePlugin(S2E* s2e): Plugin(s2e){
    }
	virtual ~SimpleBundlePlugin();
	 void initialize();
	 void slotTranslateInstructionStart(ExecutionSignal *signal,
	                                                    S2EExecutionState *state,
	                                                    TranslationBlock *tb,
	                                                    uint64_t pc);
	 void slotTranslateInstructionEnd(ExecutionSignal *signal,
	                                                    S2EExecutionState *state,
	                                                    TranslationBlock *tb,
	                                                    uint64_t pc);
	 void onInstructionExecutionBefore(S2EExecutionState* state, uint64_t pc);
	 void onInstructionExecutionAfter(S2EExecutionState* state, uint64_t pc);

};

class SimpleBundlePluginState: public PluginState
{

public:
    SimpleBundlePluginState() {
    }
    ~SimpleBundlePluginState() {}
    static PluginState *factory(Plugin*, S2EExecutionState*) {
        return new SimpleBundlePluginState();
    }
    SimpleBundlePluginState *clone() const {
        return new SimpleBundlePluginState(*this);
    }
};
} /* namespace s2e */
#endif /* SIMPLE_BUNDLEPLUGIN_H_ */
