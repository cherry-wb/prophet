/*
 * S2E Selective Symbolic Execution Framework
 *
 * Copyright (c) 2010, Dependable Systems Laboratory, EPFL
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of the Dependable Systems Laboratory, EPFL nor the
 *       names of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE DEPENDABLE SYSTEMS LABORATORY, EPFL BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * Currently maintained by:
 *    Vitaly Chipounov <vitaly.chipounov@epfl.ch>
 *    Volodymyr Kuznetsov <vova.kuznetsov@epfl.ch>
 *
 * All contributors are listed in the S2E-AUTHORS file.
 */

/**
 *  This plugin tracks the modules which are being executed at any given point.
 *  A module is a piece of code defined by a name. Currently the pieces of code
 *  are derived from the actual executable files reported by the OS monitor.
 *  TODO: allow specifying any kind of regions.
 *
 *  XXX: distinguish between processes and libraries, which should be tracked in all processes.
 *
 *  XXX: might translate a block without instrumentation and reuse it in instrumented part...
 *
 *  NOTE: it is not possible to track relationships between modules here.
 *  For example, tracking of a library of a particular process. Instead, the
 *  plugin tracks all libraries in all processes. This is because the instrumented
 *  code can be shared between different processes. We have to conservatively instrument
 *  all code, otherwise if some interesting code is translated first within the context
 *  of an irrelevant process, there would be no detection instrumentation, and when the
 *  code is executed in the relevant process, the module execution detection would fail.
 */
//#define NDEBUG


extern "C" {
#include "config.h"
#include "qemu-common.h"
#include "cpu.h"
extern CPUArchState *env;
}


#include <s2e/S2E.h>
#include <s2e/S2EExecutor.h>
#include <s2e/s2e_qemu.h>
#include <s2e/ConfigFile.h>
#include <s2e/Utils.h>
#include <s2e/Plugins/Opcodes.h>

#include "ModuleExecutionDetector.h"
#include <assert.h>
#include <sstream>
#include <llvm/Support/TimeValue.h>
using namespace s2e;
using namespace s2e::plugins;

S2E_DEFINE_PLUGIN(ModuleExecutionDetector,
                  "Plugin for monitoring module execution",
                  "ModuleExecutionDetector",
                  "Interceptor");

ModuleExecutionDetector::~ModuleExecutionDetector()
{

}

void ModuleExecutionDetector::initialize()
{
    m_Monitor = (OSMonitor*)s2e()->getPlugin("Interceptor");
    assert(m_Monitor);

    m_Monitor->onModuleLoad.connect(
        sigc::mem_fun(*this, &ModuleExecutionDetector::moduleLoadListener));

    m_Monitor->onModuleUnload.connect(
        sigc::mem_fun(*this, &ModuleExecutionDetector::moduleUnloadListener));

    m_Monitor->onProcessUnload.connect(
        sigc::mem_fun(*this, &ModuleExecutionDetector::processUnloadListener));

    s2e()->getCorePlugin()->onTranslateBlockStart.connect(
        sigc::mem_fun(*this, &ModuleExecutionDetector::onTranslateBlockStart));

    s2e()->getCorePlugin()->onTranslateBlockEnd.connect(
            sigc::mem_fun(*this, &ModuleExecutionDetector::onTranslateBlockEnd));

    s2e()->getCorePlugin()->onTranslateBlockOver.connect(
            sigc::mem_fun(*this, &ModuleExecutionDetector::onTranslateBlockOver));

    s2e()->getCorePlugin()->onException.connect(
        sigc::mem_fun(*this, &ModuleExecutionDetector::exceptionListener));

    s2e()->getCorePlugin()->onCustomInstruction.connect(
        sigc::mem_fun(*this, &ModuleExecutionDetector::onCustomInstruction));

    initializeConfiguration();
}

void ModuleExecutionDetector::initializeConfiguration()
{
    ConfigFile *cfg = s2e()->getConfig();
	m_skipprocessnum = cfg->getInt(getConfigKey() + ".skipprocessnum", 0);
    m_mainmodule = cfg->getString(getConfigKey() + ".mainmodule");
	if (m_mainmodule.length() == 0) {
		s2e()->getWarningsStream()
				<< "ModuleExecutionDetector: You must specify mainmodule to track" << '\n';
		exit(-1);
		return;
	}
    ConfigFile::string_list keyList = cfg->getListKeys(getConfigKey());

    if (keyList.size() == 0) {
        s2e()->getWarningsStream() <<  "ModuleExecutionDetector: no configuration keys!" << '\n';
    }

    m_TrackAllModules = cfg->getBool(getConfigKey() + ".trackAllModules");
    m_ConfigureAllModules = cfg->getBool(getConfigKey() + ".configureAllModules");
    //m_checkPacker = cfg->getBool(getConfigKey() + ".checkPacker",false);
    foreach2(it, keyList.begin(), keyList.end()) {
        if (*it == "trackAllModules"  || *it == "configureAllModules" || *it == "mainmodule"|| *it == "checkPacker" || *it == "skipprocessnum") {
            continue;
        }

        ModuleExecutionCfg d;
        std::stringstream s;
        s << getConfigKey() << "." << *it << ".";
        d.id = *it;

        bool ok = false;
        d.moduleName = cfg->getString(s.str() + "moduleName", "", &ok);
        if (!ok) {
            s2e()->getWarningsStream() << "You must specifiy " << s.str() + "moduleName" << '\n';
            exit(-1);
        }
        std::transform(d.moduleName.begin(), d.moduleName.end(), d.moduleName.begin(), ::tolower);

        d.kernelMode = cfg->getBool(s.str() + "kernelMode", false, &ok);
        if (!ok) {
            s2e()->getWarningsStream() << "You must specifiy " << s.str() + "kernelMode" << '\n';
            exit(-1);
        }

        ConfigFile::string_list pollingEntries = cfg->getListKeys(
    				s.str() + "ranges");

		if (pollingEntries.size() == 0) {
			Range rg;
			rg.start = 0x00000000;
			rg.end = 0xFFFFFFFF;
			d.ranges.insert(rg);
		}else{
			foreach2(it, pollingEntries.begin(), pollingEntries.end())
			{
				std::stringstream ss1;
				ss1 << s.str() << "ranges" << "." << *it;
				ConfigFile::integer_list il = cfg->getIntegerList(ss1.str());
				if (il.size() != 2) {
					s2e()->getWarningsStream() << "Range entry " << ss1.str()
							<< " must be of the form {startPc, endPc} format"
							<< '\n';
					continue;
				}

				bool ok = false;
				uint64_t start = cfg->getInt(ss1.str() + "[1]", 0, &ok);
				if (!ok) {
					s2e()->getWarningsStream()
							<< "ModuleExecutionDetector could not read "
							<< ss1.str() << "[0]" << '\n';
					continue;
				}

				uint64_t end = cfg->getInt(ss1.str() + "[2]", 0, &ok);
				if (!ok) {
					s2e()->getWarningsStream()
							<< "ModuleExecutionDetector could not read "
							<< ss1.str() << "[1]" << '\n';
					continue;
				}
				//Convert the format to native address
				Range rg;
				rg.start = start;
				rg.end = end;
				d.ranges.insert(rg);
			}
		}

        s2e()->getDebugStream() << "ModuleExecutionDetector: " <<
                "id=" << d.id << " " <<
                "moduleName=" << d.moduleName << " " <<
                "context=" << d.context  << '\n';

        if (m_ConfiguredModulesName.find(d) != m_ConfiguredModulesName.end()) {
            s2e()->getWarningsStream() << "ModuleExecutionDetector: " <<
                    "module names must be unique!" << '\n';
            exit(-1);
        }


        if (m_ConfiguredModulesId.find(d) != m_ConfiguredModulesId.end()) {
            s2e()->getWarningsStream() << "ModuleExecutionDetector: " <<
                    "module ids must be unique!" << '\n';
            exit(-1);
        }

        m_ConfiguredModulesId.insert(d);
        m_ConfiguredModulesName.insert(d);
    }
}
/*****************************************************************************/
/*****************************************************************************/
/*****************************************************************************/
bool ModuleExecutionDetector::opAddModuleConfigEntry(S2EExecutionState *state)
{
    bool ok = true;
    //XXX: 32-bits guests only
    target_ulong moduleId, moduleName, isKernelMode;

    ok &= state->readCpuRegisterConcrete(CPU_OFFSET(MODULEID), &moduleId, sizeof(moduleId));
    ok &= state->readCpuRegisterConcrete(CPU_OFFSET(MODULENAME), &moduleName, sizeof(moduleName));
    ok &= state->readCpuRegisterConcrete(CPU_OFFSET(KERNELMODE), &isKernelMode, sizeof(isKernelMode));

    if(!ok) {
        s2e()->getWarningsStream(state)
            << "ModuleExecutionDetector: Could not read parameters.\n";
        return false;
    }

    std::string strModuleId, strModuleName;
    if (!state->readString(moduleId, strModuleId)) {
        s2e()->getWarningsStream(state)
            << "ModuleExecutionDetector: Could not read the module id string.\n";
        return false;
    }

    if (!state->readString(moduleName, strModuleName)) {
        s2e()->getWarningsStream(state)
            << "ModuleExecutionDetector: Could not read the module name string.\n";
        return false;
    }

    ModuleExecutionCfg desc;
    desc.id = strModuleId;
    desc.moduleName = strModuleName;
    desc.kernelMode = (bool) isKernelMode;

    s2e()->getMessagesStream() << "ModuleExecutionDetector: Adding module " <<
            "id=" << desc.id <<
            " moduleName=" << desc.moduleName <<
            " kernelMode=" << desc.kernelMode << "\n";

    if (m_ConfiguredModulesName.find(desc) != m_ConfiguredModulesName.end()) {
        s2e()->getWarningsStream() << "ModuleExecutionDetector: " <<
                "module name " << desc.moduleName << " already exists\n";
        return false;
    }


    if (m_ConfiguredModulesId.find(desc) != m_ConfiguredModulesId.end()) {
        s2e()->getWarningsStream() << "ModuleExecutionDetector: " <<
                "module id " << desc.id << " already exists\n";
        return false;
    }

    m_ConfiguredModulesId.insert(desc);
    m_ConfiguredModulesName.insert(desc);

    return true;
}

void ModuleExecutionDetector::onCustomInstruction(
        S2EExecutionState *state,
        uint64_t operand
        )
{
    if (!OPCODE_CHECK(operand, MODULE_EXECUTION_DETECTOR_OPCODE)) {
        return;
    }

    uint64_t subfunction = OPCODE_GETSUBFUNCTION(operand);

    switch(subfunction) {
        case 0: {
            if (opAddModuleConfigEntry(state)) {
                if (s2e()->getExecutor()->getStatesCount() > 1) {
                    s2e()->getWarningsStream(state)
                            << "ModuleExecutionDetector attempts to flush the TB cache while having more than 1 state.\n"
                            << "Doing that in S2E is dangerous for many reasons, so we ignore the request.\n";
                }  else {
                    tb_flush(env);
                }

                state->setPc(state->getPc() + OPCODE_SIZE);
                throw CpuExitException();
            }
            break;
        }
    }

}


uint64_t ModuleExecutionDetector::getMainmoduleIndentity(S2EExecutionState *state) const {
  DECLARE_PLUGINSTATE(ModuleTransitionState, state);
	return		   plgState->m_mainmoduleIndentity;
}
void ModuleExecutionDetector::setMainmoduleIndentity(uint64_t mainmoduleIndentity,S2EExecutionState *state) {
   DECLARE_PLUGINSTATE(ModuleTransitionState, state);
   plgState->m_mainmoduleIndentity = mainmoduleIndentity;
}
/*****************************************************************************/
/*****************************************************************************/
/*****************************************************************************/

void ModuleExecutionDetector::moduleLoadListener(
    S2EExecutionState* state,
    const ModuleDescriptor &module)
{
    DECLARE_PLUGINSTATE(ModuleTransitionState, state);

    //If module name matches the configured ones, activate.
    s2e()->getDebugStream() << "ModuleExecutionDetector: " <<
            "Module "  << module.Name <<" PID "  << hexval(module.Pid) << " loaded - " <<
            "Base=" <<  hexval(module.LoadBase) << " Size=" << hexval(module.Size) <<
            " NativeBase=" <<  hexval(module.NativeBase) << "\n";

    const std::string *s = getModuleId(module);
	if (!isKernelMode()) {
		if (s  && m_mainmodule == *s && plgState->m_mainmoduleIndentity == 0) {//  //允许多进程，以最后一个进程为主进程 ,通过跳过参数m_skipprocessnum进行设置
			if(plgState->m_skipprocessnum < m_skipprocessnum){
				plgState->m_skipprocessnum += 1;
				return;
			}
			 plgState->m_mainmoduleIndentity = module.Pid;
			std::stringstream ss;
			ss << "ModuleExecutionDetector mainmodule：" << m_mainmodule << "PID:"
					<< hexval( plgState->m_mainmoduleIndentity);
			s2e()->getCorePlugin()->onNotifyMessage.emit(state,"mainmoduleload",ss.str());
			tb_need_flash = 1;
		} else if (s &&  plgState->m_mainmoduleIndentity == 0 && m_mainmodule != *s) {
//			fprintf(stderr,"1\n");
			return; //主模块加载之前不要加载任何其他附加模块
		} else if ( plgState->m_mainmoduleIndentity != 0 && module.Pid !=  plgState->m_mainmoduleIndentity) {
//			fprintf(stderr,"2\n");
			return; //不是作为主进程附加模块而加载的，则略过
		}else if ( plgState->m_mainmoduleIndentity == 0){
//			fprintf(stderr,"3\n");
			return;
		}
	}else{
		if (s &&  plgState->m_mainmoduleIndentity == 0 && m_mainmodule == *s) {
			 plgState->m_mainmoduleIndentity = module.LoadBase;
			std::stringstream ss;
			ss << "ModuleExecutionDetector mainmodule:" << m_mainmodule << "LoadBase:"
					<< hexval( plgState->m_mainmoduleIndentity);
			s2e()->getCorePlugin()->onNotifyMessage.emit(state,"mainmoduleload",ss.str());
		}
	}

    ModuleExecutionCfg cfg;
    cfg.moduleName = module.Name;

    if (m_ConfigureAllModules) {
        if (plgState->exists(&module, true)) {
            s2e()->getDebugStream() << " [ALREADY REGISTERED]" << '\n';
        }else {
            s2e()->getDebugStream() << " [REGISTERING]" << '\n';
            onModuleLoad.emit(state, module);
            plgState->loadDescriptor(module, true);
        }
        return;
    }

    ConfiguredModulesByName::iterator it = m_ConfiguredModulesName.find(cfg);
    if (it != m_ConfiguredModulesName.end()) {
        if (plgState->exists(&module, true)) {
            s2e()->getDebugStream() << " [ALREADY REGISTERED ID=" << (*it).id << "]" << '\n';
        }else {
            s2e()->getDebugStream() << " [REGISTERING ID=" << (*it).id << "]" << '\n';
            onModuleLoad.emit(state, module);
            plgState->loadDescriptor(module, true);
        }
        return;
    }

    s2e()->getDebugStream() << '\n';

    if (m_TrackAllModules) {
        if (!plgState->exists(&module, false)) {
            s2e()->getDebugStream() << " [REGISTERING NOT TRACKED]" << '\n';
            onModuleLoad.emit(state, module);
            plgState->loadDescriptor(module, false);
        }
        return;
    }
}

void ModuleExecutionDetector::moduleUnloadListener(
    S2EExecutionState* state, const ModuleDescriptor &module)
{
    DECLARE_PLUGINSTATE(ModuleTransitionState, state);

    s2e()->getDebugStream() << "Module " << module.Name << " is unloaded" << '\n';

    plgState->unloadDescriptor(module);
}



void ModuleExecutionDetector::processUnloadListener(
    S2EExecutionState* state, const  ProcessDescriptor &pd)
{
    DECLARE_PLUGINSTATE(ModuleTransitionState, state);

    s2e()->getDebugStream() << "Process " << hexval(pd.pid) << " is unloaded\n";

    plgState->unloadDescriptorsWithPid(pd.pid);
}


//Check that the module id is valid
bool ModuleExecutionDetector::isModuleConfigured(const std::string &moduleId) const
{
    ModuleExecutionCfg cfg;
    cfg.id = moduleId;

    return m_ConfiguredModulesId.find(cfg) != m_ConfiguredModulesId.end();
}
bool ModuleExecutionDetector::printModuleConfigured() const
{
	foreach2(it, m_ConfiguredModulesId.begin(), m_ConfiguredModulesId.end())
	{
    	 std::cout << "name:"<< (*it).moduleName << " id:" << (*it).id << "\n";
    }
    return true;
}

/*****************************************************************************/
/*****************************************************************************/
/*****************************************************************************/

const ModuleDescriptor *ModuleExecutionDetector::getModule(S2EExecutionState *state, uint64_t pc, bool tracked)
{
    DECLARE_PLUGINSTATE(ModuleTransitionState, state);
    uint64_t pid = m_Monitor->getPid(state, pc);

    const ModuleDescriptor *currentModule =
            plgState->getDescriptor(pid, pc, tracked);
    return currentModule;
}

const std::string *ModuleExecutionDetector::getModuleId(const ModuleDescriptor &desc) const
{
    ModuleExecutionCfg cfg;
    cfg.moduleName = desc.Name;

    ConfiguredModulesByName::iterator it = m_ConfiguredModulesName.find(cfg);
    if (it == m_ConfiguredModulesName.end()) {
        return NULL;
    }
    return &(*it).id;
}

bool ModuleExecutionDetector::goahead(const ModuleDescriptor* currentModule,
		uint64_t pc) {
	if (currentModule) {
		ModuleExecutionCfg cfg;
		cfg.moduleName = currentModule->Name;
		ConfiguredModulesByName::iterator it = m_ConfiguredModulesName.find(
				cfg);
		bool found = (it != m_ConfiguredModulesName.end());
		bool rfound = false;
		if (found) {
			foreach2(rgit, (*it).ranges.begin(), (*it).ranges.end())
			{
				if ((pc >= (*rgit).start) && (pc <= (*rgit).end)) {
					rfound = true;
					break;
				}
			}
		}
		bool res = found && rfound;
		return res;
	} else {
		return false;
	}
}
bool ModuleExecutionDetector::goahead(S2EExecutionState *state,uint64_t pc,bool isDataMemoryAccess) {
    DECLARE_PLUGINSTATE(ModuleTransitionState, state);
    uint64_t pid = m_Monitor->getPid(state, pc);
    const ModuleDescriptor *currentModule =
            plgState->getDescriptor(pid, pc);
    bool shouldgo = goahead(currentModule, pc);

    return shouldgo;
}
void ModuleExecutionDetector::connectExecution(
		const ModuleDescriptor* currentModule, uint64_t pc,
		ExecutionSignal* signal) {
	signal->connect(sigc::mem_fun(*this, &ModuleExecutionDetector::onExecution));
}


void ModuleExecutionDetector::onTranslateBlockStart(
    ExecutionSignal *signal,
    S2EExecutionState *state,
    TranslationBlock *tb,
    uint64_t pc)
{
    DECLARE_PLUGINSTATE(ModuleTransitionState, state);

    uint64_t pid = m_Monitor->getPid(state, pc);

    const ModuleDescriptor *currentModule =
            plgState->getDescriptor(pid, pc);

    if (currentModule) {
        //S2E::printf(s2e()->getDebugStream(), "Translating block %#"PRIx64" belonging to %s\n",pc, currentModule->Name.c_str());
        connectExecution(currentModule, pc, signal);
        if (pc >= s2e()->getTranslateWatchStart()
        				&& pc <= s2e()->getTranslateWatchEnd()) {
			std::stringstream ss;
			ss << "start to translate basicblock. start：" << hexval(tb->pc) << "  size："<<hexval(tb->size) <<"\n";
			s2e()->getDebugStream() << ss.str() ;
			s2e()->getCorePlugin()->onNotifyMessage.emit(state,"translateblockstart",ss.str());
		}
        onModuleTranslateBlockStart.emit(signal, state, *currentModule, tb, pc);
    }
//    else if(m_mainmoduleIndentity!=0  && m_mainmoduleIndentity == m_Monitor->getPid(state, state->getPc())){
//    	ModuleDescriptor _tmpmd;
//		_tmpmd.Name = "unknown";
//    	onModuleTranslateBlockStart.emit(signal, state, _tmpmd, tb, pc);
//	  if (pc >= s2e()->getTranslateWatchStart()
//							&& pc <= s2e()->getTranslateWatchEnd()) {
//				std::stringstream ss;
//				ss << "start to translate basicblock. start：" << hexval(tb->pc) << "  size："<<hexval(tb->size) <<"\n";
//				s2e()->getDebugStream() << ss.str() ;
//				s2e()->getCorePlugin()->onNotifyMessage.emit(state,"translateblockstart",ss.str());
//			}
//    }
}

void ModuleExecutionDetector::onTranslateBlockEnd(
        ExecutionSignal *signal,
        S2EExecutionState* state,
        TranslationBlock *tb,
        uint64_t endPc,
        bool staticTarget,
        uint64_t targetPc)
{
    DECLARE_PLUGINSTATE(ModuleTransitionState, state);

    const ModuleDescriptor *currentModule =
            getCurrentDescriptor(state);

    if (!currentModule) {
        // Outside of any module, do not need
        // to instrument tb exits.
        return;
    }


    if (staticTarget) {
        const ModuleDescriptor *targetModule =
            plgState->getDescriptor(m_Monitor->getPid(state, targetPc), targetPc);

        if (currentModule && targetModule != currentModule) {
            //Only instrument in case there is a module change
            //TRACE("Static transition from %#"PRIx64" to %#"PRIx64"\n",
            //    endPc, targetPc);
        	connectExecution(currentModule, targetPc, signal);
        }
    }else {
        //TRACE("Dynamic transition from %#"PRIx64" to %#"PRIx64"\n",
        //        endPc, targetPc);
        //In case of dynamic targets, conservatively
        //instrument code.
    	 if (currentModule)
    	{
    		 connectExecution(currentModule, targetPc, signal);
    	}
    }

    if (currentModule) {
       onModuleTranslateBlockEnd.emit(signal, state, *currentModule, tb, endPc,
        staticTarget, targetPc);
    }
//    else if(m_mainmoduleIndentity!=0 && m_mainmoduleIndentity == m_Monitor->getPid(state, state->getPc())){
//    	ModuleDescriptor _tmpmd;
//    	_tmpmd.Name = "unknown";
//        onModuleTranslateBlockEnd.emit(signal, state, _tmpmd, tb, endPc,
//         staticTarget, targetPc);
//    }

}
void ModuleExecutionDetector::onTranslateBlockOver(
        S2EExecutionState* state,
        TranslationBlock *tb,
        uint64_t endPc)
{
    const ModuleDescriptor *currentModule =
            getCurrentDescriptor(state);

    if (!currentModule) {
        // Outside of any module, do not need
        // to instrument tb exits.
        return;
    }

    if (currentModule) {
    	onModuleTranslateBlockOver.emit(state, *currentModule, tb, endPc);
    }
//    else if(m_mainmoduleIndentity!=0 && m_mainmoduleIndentity == m_Monitor->getPid(state, state->getPc())){
//    	ModuleDescriptor _tmpmd;
//    	_tmpmd.Name = "unknown";
//    	onModuleTranslateBlockOver.emit(state, _tmpmd, tb, endPc);
//    }

}
void ModuleExecutionDetector::exceptionListener(
                       S2EExecutionState* state,
                       unsigned intNb,
                       uint64_t pc
                       )
{
    //std::cout << "Exception index " << intNb << '\n';
    //onExecution(state, pc);

    DECLARE_PLUGINSTATE(ModuleTransitionState, state);

    //gTRACE("pid=%#"PRIx64" pc=%#"PRIx64"\n", pid, pc);
    if (plgState->m_PreviousModule != NULL) {
        onModuleTransition.emit(state, plgState->m_PreviousModule, NULL);
        plgState->m_PreviousModule = NULL;
    }
}


/**
 *  This returns the descriptor of the module that is currently being executed.
 *  This works only when tracking of all modules is activated.
 */
const ModuleDescriptor *ModuleExecutionDetector::getCurrentDescriptor(S2EExecutionState* state) const
{
    DECLARE_PLUGINSTATE_CONST(ModuleTransitionState, state);

    uint32_t pc = state->getPc();
    uint64_t pid = m_Monitor->getPid(state, state->getPc());

    return plgState->getDescriptor(pid, pc);
}
const ModuleDescriptor *ModuleExecutionDetector::getDescriptor(S2EExecutionState* state, uint64_t pid, uint64_t pc) const
{
    DECLARE_PLUGINSTATE_CONST(ModuleTransitionState, state);
    return plgState->getDescriptor(pid, pc);
}
void ModuleExecutionDetector::onExecution(
    S2EExecutionState *state, uint64_t pc)
{
    DECLARE_PLUGINSTATE(ModuleTransitionState, state);

    const ModuleDescriptor *currentModule = getCurrentDescriptor(state);

    //gTRACE("pid=%#"PRIx64" pc=%#"PRIx64"\n", pid, pc);
    if (plgState->m_PreviousModule != currentModule) {
#if 0
        if (currentModule) {
            s2e_debug_print("Entered module %s\n", currentModule->descriptor.Name.c_str());
        }else {
            s2e_debug_print("Entered unknown module\n");
        }
#endif
        onModuleTransition.emit(state, plgState->m_PreviousModule, currentModule);

        plgState->m_PreviousModule = currentModule;
    }
}

void ModuleExecutionDetector::dumpMemory(S2EExecutionState *state,
                                         llvm::raw_ostream &os_llvm,
                                         uint64_t va, unsigned count)
{
    std::stringstream os;

    uint64_t sp = va;
    for (unsigned i=0; i<count; ++i) {
        klee::ref<klee::Expr> val = state->readMemory(sp + i * sizeof(uint32_t), klee::Expr::Int32);
        if (val.isNull()) {
            continue;
        }

        klee::ConstantExpr *ce = dyn_cast<klee::ConstantExpr>(val);
        if (ce) {
            os << std::hex << "0x" << sp + i * sizeof(uint32_t) << " 0x" << std::setw(sizeof(uint32_t)*2) << std::setfill('0') << val;
            os << std::setfill(' ');

            uint32_t v = ce->getZExtValue(ce->getWidth());
            const ModuleDescriptor *md = getModule(state,  v, false);
            if (md) {
               os << " " << md->Name <<  " 0x" << md->ToNativeBase(v);
               os << " +0x" << md->ToRelative(v);
            }
        }else {
            os << std::hex << "0x" << sp + i * sizeof(uint32_t) << val;
        }

        os << '\n';
    }

    os_llvm << os.str();
}

/*****************************************************************************/
/*****************************************************************************/
/*****************************************************************************/

ModuleTransitionState::ModuleTransitionState()
{
    m_PreviousModule = NULL;
    m_CachedModule = NULL;
    m_mainmoduleIndentity = 0;
    m_skipprocessnum = 0;
}

ModuleTransitionState::~ModuleTransitionState()
{
    foreach2(it, m_Descriptors.begin(), m_Descriptors.end()) {
        delete *it;
    }

    foreach2(it, m_NotTrackedDescriptors.begin(), m_NotTrackedDescriptors.end()) {
        delete *it;
    }
}

ModuleTransitionState* ModuleTransitionState::clone() const
{
    ModuleTransitionState *ret = new ModuleTransitionState();

    foreach2(it, m_Descriptors.begin(), m_Descriptors.end()) {
        ret->m_Descriptors.insert(new ModuleDescriptor(**it));
    }

    foreach2(it, m_NotTrackedDescriptors.begin(), m_NotTrackedDescriptors.end()) {
        assert(*it != m_CachedModule && *it != m_PreviousModule);
        ret->m_NotTrackedDescriptors.insert(new ModuleDescriptor(**it));
    }

    if (m_CachedModule) {
        DescriptorSet::iterator it = ret->m_Descriptors.find(m_CachedModule);
        assert(it != ret->m_Descriptors.end());
        ret->m_CachedModule = *it;
    }

    if (m_PreviousModule) {
        DescriptorSet::iterator it = ret->m_Descriptors.find(m_PreviousModule);
        assert(it != ret->m_Descriptors.end());
        ret->m_PreviousModule = *it;
    }
    ret->m_mainmoduleIndentity = m_mainmoduleIndentity;
    return ret;
}

PluginState* ModuleTransitionState::factory(Plugin *p, S2EExecutionState *state)
{
    ModuleTransitionState *s = new ModuleTransitionState();

    p->s2e()->getDebugStream() << "Creating initial module transition state" << '\n';

    return s;
}

const ModuleDescriptor *ModuleTransitionState::getDescriptor(uint64_t pid, uint64_t pc, bool tracked) const
{
    if (m_CachedModule) {
        const ModuleDescriptor &md = *m_CachedModule;
        uint64_t prevModStart = md.LoadBase;
        uint64_t prevModSize = md.Size;
        uint64_t prevModPid = md.Pid;
        if (pid == prevModPid && pc >= prevModStart && pc < prevModStart + prevModSize) {
            //We stayed in the same module
            return m_CachedModule;
        }
    }

    ModuleDescriptor d;
    d.Pid = pid;
    d.LoadBase = pc;
    d.Size = 1;
    DescriptorSet::iterator it = m_Descriptors.find(&d);
    if (it != m_Descriptors.end()) {
        m_CachedModule = *it;
        return *it;
    }

    m_CachedModule = NULL;

    if (!tracked) {
        it = m_NotTrackedDescriptors.find(&d);
        if (it != m_NotTrackedDescriptors.end()) {
            //XXX: implement proper caching
            assert(*it != m_CachedModule && *it != m_PreviousModule);
            return *it;
        }
    }

    return NULL;
}

bool ModuleTransitionState::loadDescriptor(const ModuleDescriptor &desc, bool track)
{
    if (track) {
        m_Descriptors.insert(new ModuleDescriptor(desc));
    }else {
        if (m_NotTrackedDescriptors.find(&desc) == m_NotTrackedDescriptors.end()) {
            m_NotTrackedDescriptors.insert(new ModuleDescriptor(desc));
        }
        else {
            return false;
        }
    }
    return true;
}

void ModuleTransitionState::unloadDescriptor(const ModuleDescriptor &desc)
{
    ModuleDescriptor d;
    d.LoadBase = desc.LoadBase;
    d.Pid = desc.Pid;
    d.Size = desc.Size;

    DescriptorSet::iterator it = m_Descriptors.find(&d);
    if (it != m_Descriptors.end()) {
        if (m_CachedModule == *it) {
            m_CachedModule = NULL;
        }

        if (m_PreviousModule == *it) {
            m_PreviousModule = NULL;
        }

        const ModuleDescriptor *md = *it;
        size_t s = m_Descriptors.erase(*it);
        assert(s == 1);
        delete md;
    }

    it = m_NotTrackedDescriptors.find(&d);
    if (it != m_NotTrackedDescriptors.end()) {
        assert(*it != m_CachedModule && *it != m_PreviousModule);
        const ModuleDescriptor *md = *it;
        size_t s = m_NotTrackedDescriptors.erase(*it);
        assert(s == 1);
        delete md;
    }
}

void ModuleTransitionState::unloadDescriptorsWithPid(uint64_t pid)
{
    DescriptorSet::iterator it, it1;

    for (it = m_Descriptors.begin(); it != m_Descriptors.end(); ) {
        if ((*it)->Pid != pid) {
            ++it;
        }else {
            it1 = it;
            ++it1;

            if (m_CachedModule == *it) {
                m_CachedModule = NULL;
            }

            if (m_PreviousModule == *it) {
                m_PreviousModule = NULL;
            }

            const ModuleDescriptor *md = *it;
            m_Descriptors.erase(*it);
            delete md;

            it = it1;
        }
    }

    //XXX: avoid copy/paste
    for (it = m_NotTrackedDescriptors.begin(); it != m_NotTrackedDescriptors.end(); ) {
        if ((*it)->Pid != pid) {
            ++it;
        }else {
            it1 = it;
            ++it1;

            if (m_CachedModule == *it) {
                m_CachedModule = NULL;
            }

            if (m_PreviousModule == *it) {
                m_PreviousModule = NULL;
            }

            const ModuleDescriptor *md = *it;
            m_NotTrackedDescriptors.erase(*it);
            delete md;

            it = it1;
        }
    }
}

bool ModuleTransitionState::exists(const ModuleDescriptor *desc, bool tracked) const
{
    bool ret;
    ret = m_Descriptors.find(desc) != m_Descriptors.end();
    if (ret) {
        return ret;
    }

    if (tracked) {
        return false;
    }

    return m_NotTrackedDescriptors.find(desc) != m_NotTrackedDescriptors.end();
}
