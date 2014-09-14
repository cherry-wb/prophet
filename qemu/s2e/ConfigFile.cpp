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
 *    Volodymyr Kuznetsov <vova.kuznetsov@epfl.ch>
 *    Vitaly Chipounov <vitaly.chipounov@epfl.ch>
 *
 * All contributors are listed in the S2E-AUTHORS file.
 */

extern "C" {
#include <qemu-common.h>
#include <cpu-all.h>
#include <exec-all.h>
#include "cpu.h"
#include <disas.h>
extern CPUArchState *env;
}


#include "ConfigFile.h"

#include <s2e/Utils.h>
#include <s2e/S2E.h>
#include <s2e/S2EExecutionState.h>
#include <s2e/S2EExecutor.h>
#include <s2e/Plugins/StackMonitor.h>
#include <s2e/Plugins/EXT/HeapMonitor.h>
#include <ctype.h>
#include <stdlib.h>
#include <sstream>
#include <iostream>
extern "C" {
#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>
}

namespace s2e {
using namespace std;

ConfigFile::ConfigFile(const std::string &configFileName)
{
    m_luaState = lua_open();
    luaL_openlibs(m_luaState);
    luaopen_table(m_luaState);
    luaopen_string(m_luaState);
    luaopen_debug(m_luaState);
  
    if(!configFileName.empty()) {
        if(luaL_loadfile(m_luaState, configFileName.c_str()) ||
                    lua_pcall(m_luaState, 0, 0, 0)) {
            luaError("Can not run configuration file:\n    %s\n",
                    lua_tostring(m_luaState, -1));
        }

        //Register S2E API
        RegisterS2EApi();
    }
}

ConfigFile::~ConfigFile()
{
    lua_close(m_luaState);
}

template<> inline
const char* ConfigFile::getTypeName<bool>() { return "boolean"; }

template<> inline
const char* ConfigFile::getTypeName<int64_t>() { return "integer"; }

template<> inline
const char* ConfigFile::getTypeName<double>() { return "double"; }

template<> inline
const char* ConfigFile::getTypeName<string>() { return "string"; }

template<> inline
const char* ConfigFile::getTypeName<ConfigFile::string_list>() {
  return "lua_list with only string values";
}

template<> inline
const char* ConfigFile::getTypeName<ConfigFile::integer_list>() {
  return "lua_list with only integer values";
}

template<> inline
const char* ConfigFile::getTypeName<ConfigFile::_key_list>() {
  return "lua_table with only string keys";
}

template<> inline
const char* ConfigFile::getTypeName<ConfigFile::_list_size>() {
  return "lua_table";
}

template<> inline
bool ConfigFile::getLuaValue(bool *res, const bool& def, int index) {
    bool ok = lua_isboolean(m_luaState, index);
    *res = ok ? lua_toboolean(m_luaState, index) : def;
    return ok;
}

template<> inline
bool ConfigFile::getLuaValue(int64_t* res, const int64_t& def, int index) {
    bool ok = lua_isnumber(m_luaState, index);
    *res = ok ? lua_tointeger(m_luaState, index) : def;
    return ok;
}

template<> inline
bool ConfigFile::getLuaValue(double* res, const double& def, int index) {
    bool ok = lua_isnumber(m_luaState, index);
    *res = ok ? lua_tonumber(m_luaState, index) : def;
    return ok;
}

template<> inline
bool ConfigFile::getLuaValue(string* res, const string& def, int index) {
    bool ok = lua_isstring(m_luaState, index);
    *res = ok ? lua_tostring(m_luaState, index) : def;
    return ok;
}

template<> inline
bool ConfigFile::getLuaValue(string_list* res, const string_list& def, int index) {
    bool ok = lua_istable(m_luaState, index);
    if(!ok) { *res = def; return ok; }
  
    /* read table as array */
    for(int i=1; ; ++i) {
        lua_rawgeti(m_luaState, index, i);
        if(lua_isnil(m_luaState, -1)) {
            lua_pop(m_luaState, 1);
            break;
        }
        if(lua_isstring(m_luaState, -1)) {
            res->push_back(lua_tostring(m_luaState, -1));
            lua_pop(m_luaState, 1);
        } else {
            lua_pop(m_luaState, 1);
            *res = def;
            return false;
        }
    }
  
    return true;
}

template<> inline
bool ConfigFile::getLuaValue(integer_list* res, 
                             const integer_list& def, int index) {
    bool ok = lua_istable(m_luaState, index);
    if(!ok) { *res = def; return ok; }
  
    /* read table as array */
    for(int i=1; ; ++i) {
        lua_rawgeti(m_luaState, index, i);
        if(lua_isnil(m_luaState, -1)) {
            lua_pop(m_luaState, 1);
            break;
        }
        if(lua_isstring(m_luaState, -1)) {
            res->push_back(lua_tointeger(m_luaState, -1));
            lua_pop(m_luaState, 1);
        } else {
            lua_pop(m_luaState, 1);
            *res = def;
            return false;
        }
    }
  
    return true;
}

template<> inline
bool ConfigFile::getLuaValue(_list_size* res, const _list_size& def, int index) {
    bool ok = lua_istable(m_luaState, index);
    if(!ok) { *res = def; return ok; }

    /* read table as array */
    res->size = 0;
    for(int i=1; ; ++i) {
        lua_rawgeti(m_luaState, index, i);
        if(lua_isnil(m_luaState, -1)) {
            lua_pop(m_luaState, 1);
            break;
        }
        res->size += 1;
        lua_pop(m_luaState, 1);
    }

    return true;
}

template<> inline
bool ConfigFile::getLuaValue(_key_list* res, const _key_list& def, int index) {
    bool ok = lua_istable(m_luaState, index);
    if(!ok) { *res = def; return ok; }

    lua_pushnil(m_luaState);  /* first key */

    /* table is in the stack at index-1 */
    while(lua_next(m_luaState, index-1) != 0) {
        /* uses 'key' (at index -2) and 'value' (at index -1) */

        if (!lua_isstring(m_luaState, -2)) {
            *res = def;
            return false;
        }

        res->keys.push_back(lua_tostring(m_luaState, -2));

        /* removes 'value'; keeps 'key' for next iteration */
        lua_pop(m_luaState, 1);
    }

    return true;
}

template<typename T> inline
T ConfigFile::getValueT(const std::string& name, const T& def, bool *ok)
{
	assert(name.size() != 0);    
    string expr = "return " + name;
  
    if(luaL_loadstring(m_luaState, expr.c_str()) ||
                    lua_pcall(m_luaState, 0, 1, 0)) {
    	if(!strstr(name.c_str(),"so_path"))
    		luaWarning("Can not get configuration value '%s':\n    %s\n",
    				name.c_str(), lua_tostring(m_luaState, -1));
        lua_pop(m_luaState, 1);
        if(ok) *ok = false;
        return def;
    }
  
    T res;
    bool _ok = getLuaValue(&res, def, -1);
    if(ok) *ok = _ok;
  
    if(!_ok && !strstr(name.c_str(),"so_path")) {
        luaWarning("Can not get configuration value '%s':\n    "
                "value of type %s can not be converted to %s\n",
                name.c_str(), lua_typename(m_luaState,
                    lua_type(m_luaState, -1)),
                getTypeName<T>());
    }
  
    lua_pop(m_luaState, 1);
    return res;
}

bool ConfigFile::getBool(const string& name, bool def, bool *ok)
{
    return getValueT(name, def, ok);
}

int64_t ConfigFile::getInt(const string& name, int64_t def, bool *ok)
{
    return getValueT(name, def, ok);
}

double ConfigFile::getDouble(const string& name, double def, bool *ok)
{
    return getValueT(name, def, ok);
}

string ConfigFile::getString(
            const string& name, const string& def, bool *ok)
{
    return getValueT(name, def, ok);
}

ConfigFile::string_list ConfigFile::getStringList(
            const std::string& name, const string_list& def, bool *ok)
{
    return getValueT(name, def, ok);
}

ConfigFile::integer_list ConfigFile::getIntegerList(
            const std::string& name, const integer_list& def, bool *ok)
{
    return getValueT(name, def, ok);
}

int ConfigFile::getListSize(const std::string& name, bool *ok)
{
    static const _list_size l = { 0 };
    return getValueT(name, l, ok).size;
}

ConfigFile::string_list ConfigFile::getListKeys(const std::string& name, bool *ok)
{
    static const _key_list l={std::vector<std::string>(0)};
    return getValueT(name, l, ok).keys;
}

bool ConfigFile::hasKey(const std::string& name)
{
	assert(name.size() != 0);
    string expr = "return " + name;

    if(luaL_loadstring(m_luaState, expr.c_str()) ||
                    lua_pcall(m_luaState, 0, 1, 0))
        return false;

    bool ok = !lua_isnil(m_luaState, -1);
    lua_pop(m_luaState, 1);

    return ok;
}

//This is called from the QEMU monitor
void ConfigFile::invokeLuaCommand(const char *cmd)
{
    if (luaL_dostring(m_luaState, cmd)) {
        luaWarning("Could not run '%s':\n    %s\n",
                    cmd, lua_tostring(m_luaState, -1));
        //lua_pop(m_luaState, 1);
    }
}

bool ConfigFile::isFunctionDefined(const std::string &name) const
{
    bool ret = true;
    lua_State *L = m_luaState;
    lua_getfield(L, LUA_GLOBALSINDEX, name.c_str());
    if (lua_isnil(L,-1)) {
        ret = false;
    }
    lua_pop(L,1);

    return ret;
}

//////////////////////////////////////////////////

#if 0
int ConfigFile::report (lua_State *L, int status)
{
  if (status) {
    const char *msg = lua_tostring(L, -1);
    if (msg == NULL) msg = "(error with no message)";
    g_s2e->getDebugStream() << "ERROR: "<< msg << '\n';
    lua_pop(L, 1);
  }
  return status;
}
#endif


#if 0
void ConfigFile::invokeAnnotation(const std::string &annotation, S2EExecutionState *param)
{
    lua_State *L = m_luaState;

    S2ELUAExecutionState state(param);

    lua_getfield(L, LUA_GLOBALSINDEX, annotation.c_str());
    Lunar<S2ELUAExecutionState>::push(L, &state);
    lua_call(L, 1, 0);

    //report(L, Lunar<S2ELUAApi>::call(L, annotation.c_str(), 1, 0, tb) < 0);
}
#endif

int ConfigFile::RegisterS2EApi()
{
    Lunar<S2ELUAExecutionState>::Register(m_luaState);
    return 0;
}


//////////////////////////////////////////////////
const char S2ELUAExecutionState::className[] = "S2ELUAExecutionState";

Lunar<S2ELUAExecutionState>::RegType S2ELUAExecutionState::methods[] = {
  LUNAR_DECLARE_METHOD(S2ELUAExecutionState, writeRegister),
  LUNAR_DECLARE_METHOD(S2ELUAExecutionState, writeRegisterSymb),
  LUNAR_DECLARE_METHOD(S2ELUAExecutionState, readRegister),
  LUNAR_DECLARE_METHOD(S2ELUAExecutionState, readParameter),
  LUNAR_DECLARE_METHOD(S2ELUAExecutionState, writeParameter),
  LUNAR_DECLARE_METHOD(S2ELUAExecutionState, writeMemorySymb),
  LUNAR_DECLARE_METHOD(S2ELUAExecutionState, readMemory),
  LUNAR_DECLARE_METHOD(S2ELUAExecutionState, writeMemory),
  LUNAR_DECLARE_METHOD(S2ELUAExecutionState, isSpeculative),
  LUNAR_DECLARE_METHOD(S2ELUAExecutionState, getID),

  LUNAR_DECLARE_METHOD(S2ELUAExecutionState, readParameterSymb),
  LUNAR_DECLARE_METHOD(S2ELUAExecutionState, readMemorySymb),
  LUNAR_DECLARE_METHOD(S2ELUAExecutionState, isForkingEnabled),  //cherry
  LUNAR_DECLARE_METHOD(S2ELUAExecutionState, isRunningConcrete),  //cherry
  LUNAR_DECLARE_METHOD(S2ELUAExecutionState, isSymbolicExecutionEnabled), //cherry
  LUNAR_DECLARE_METHOD(S2ELUAExecutionState, getSp),  //cherry
  LUNAR_DECLARE_METHOD(S2ELUAExecutionState, getDisasm),  //cherry
  LUNAR_DECLARE_METHOD(S2ELUAExecutionState, getFileName),  //cherry
  LUNAR_DECLARE_METHOD(S2ELUAExecutionState, searchMemory),
  LUNAR_DECLARE_METHOD(S2ELUAExecutionState, dumpInfo),
  LUNAR_DECLARE_METHOD(S2ELUAExecutionState, setTranslateStartAndEnd),
  LUNAR_DECLARE_METHOD(S2ELUAExecutionState, setExecuteStartAndEnd),
  LUNAR_DECLARE_METHOD(S2ELUAExecutionState, getTranslateStartAndEnd),
  LUNAR_DECLARE_METHOD(S2ELUAExecutionState, getExecuteStartAndEnd),
  LUNAR_DECLARE_METHOD(S2ELUAExecutionState, searchFirstSymMemory),
  LUNAR_DECLARE_METHOD(S2ELUAExecutionState, setMainProcess),

  {0,0}
};


S2ELUAExecutionState::S2ELUAExecutionState(lua_State *L)
{
    g_s2e->getDebugStream() << "Creating S2ELUAExecutionState" << '\n';
}

S2ELUAExecutionState::S2ELUAExecutionState(S2EExecutionState *s)
{
	 if (s) {
		m_state = s;
		m_id = s->getID();
	}
    g_s2e->getDebugStream() << "Creating S2ELUAExecutionState" << '\n';
}

S2ELUAExecutionState::~S2ELUAExecutionState()
{
    g_s2e->getDebugStream() << "Deleting S2ELUAExecutionState" << '\n';
}

// Read a function input parameter, optionally the calling convention
// can be specified. If omitted, a sensible one is picked up for each architecture
int S2ELUAExecutionState::readParameter(lua_State *L)
{
    uint64_t val = 0;
    uint32_t param = luaL_checkint(L, 1);
    std::string regstr;

    g_s2e->getDebugStream() << "S2ELUAExecutionState: Reading parameter " << param
            << " from stack" << '\n';

    // Optionally specify the calling convention
    if (lua_isstring(L, 2)) {
        regstr = luaL_checkstring(L, 2);
    } else {
#if defined(TARGET_I386)
        regstr = "cdecl";
#elif defined(TARGET_ARM)
        regstr = "aapcs";
#else
        regstr = "cdecl";
#endif
    }

    if (regstr == "cdecl") {
        val = readParameterCdecl(L, param);
    } else
    if (regstr == "aapcs") {
        val = readParameterAAPCS(L, param);
    }
    // TODO: implement more calling conventions

    lua_pushnumber(L, val);        /* first result */
    return 1;
}

uint64_t S2ELUAExecutionState::readParameterAAPCS(lua_State *L, uint32_t param)
{
  uint64_t val = 0;
#ifdef TARGET_ARM
  if (param <= 3) {
      if (!m_state->readCpuRegisterConcrete(CPU_OFFSET(regs[param]), &val, CPU_REG_SIZE))
          g_s2e->getDebugStream() << "S2ELUAExecutionState: could not read parameter " << param << "\n";
  }
#endif
  return val;
}

// Reads a concrete value from the stack
// XXX Not correct for function parameters for 32 bit linux kernel
uint64_t S2ELUAExecutionState::readParameterCdecl(lua_State *L, uint32_t param)
{
    uint64_t val = 0;
#ifdef TARGET_I386
    uint32_t size = sizeof (uint32_t);
    target_ulong sp = m_state->getSp() + (param + 1) * size;

#ifdef TARGET_X86_64
    if ((env->hflags & HF_CS64_MASK) && param > 5) {
        sp = m_state->getSp() + (param - 5) * CPU_REG_SIZE;
    }
    if ((env->hflags & HF_CS64_MASK) && param < 6) {
        unsigned int offset = 0;
        switch (param) {
        default:
        case 0: offset = CPU_OFFSET(regs[R_EDI]); break;
        case 1: offset = CPU_OFFSET(regs[R_ESI]); break;
        case 2: offset = CPU_OFFSET(regs[R_EDX]); break;
        case 3: offset = CPU_OFFSET(regs[R_ECX]); break;
        case 4: offset = CPU_OFFSET(regs[8]);     break;
        case 5: offset = CPU_OFFSET(regs[9]);     break;
        }

        if (!m_state->readCpuRegisterConcrete(offset, &val, sizeof (val)))
            g_s2e->getDebugStream() << "S2ELUAExecutionState: could not read"
                " parameter " << param <<
                " at CPU->regs[" << hexval(CPU_OFFSET(PROG_COUNTER) - offset) << "]\n";
    } else
#endif /* TARGET_X86_64 */
    if (!m_state->readMemoryConcrete(sp, &val, size)) {
        g_s2e->getDebugStream() << "S2ELUAExecutionState: could not read"
                " parameter " << param << " at "<< hexval(sp) << '\n';
    }
#endif
    return val;
}

int S2ELUAExecutionState::readParameterSymb(lua_State *L)
{
    uint32_t param = luaL_checkint(L, 1);

    g_s2e->getDebugStream() << "S2ELUAExecutionState: Reading Symb parameter " << param
            << " from stack" << '\n';

    uint32_t size = sizeof (uint32_t);
    target_ulong sp = m_state->getSp() + (param + 1) * size;
    try {
		uint32_t address = sp;
		klee::ref<klee::Expr> symValue;
		if (size == 4) {
			symValue = m_state->readMemory(address, klee::Expr::Int32);
		} else if (size == 1) {
			symValue = m_state->readMemory(address, klee::Expr::Int8);
		} else if (size == 2) {
			symValue = m_state->readMemory(address, klee::Expr::Int16);
		} else {
			symValue = klee::ref<klee::Expr>(0);
		}
		if (symValue.isNull()) {
			lua_pushstring(L, "error");
		} else {
			std::string expstr;
			llvm::raw_string_ostream exps(expstr);
			exps << symValue;
			lua_pushstring(L, exps.str().c_str());
		}
	} catch (...) {
		lua_pushstring(L, "error");
		return 1;
	}
    return 1;
}
// Writes a concrete value to the stack
// XXX Not correct for function parameters for 32 bit linux kernel
int S2ELUAExecutionState::writeParameter(lua_State *L)
{
    uint32_t param = luaL_checkint(L, 1);
    uint64_t val = luaL_checkint(L, 2);

    std::string regstr;

    g_s2e->getDebugStream() << "S2ELUAExecutionState: Writing parameter " << param
            << " for function.\n";

    // Optionally specify the calling convention
    if (lua_isstring(L, 3)) {
        regstr = luaL_checkstring(L, 3);
    } else {
#if defined(TARGET_I386)
        regstr = "cdecl";
#elif defined(TARGET_ARM)
        regstr = "aapcs";
#else
        regstr = "cdecl";
#endif
    }

    bool ok = false;
    if (regstr == "cdecl") {
        ok = writeParameterCdecl(L, param, val);
    } else
    if (regstr == "aapcs") {
        ok = writeParameterAAPCS(L, param, val);
    }
    // TODO: implement more calling conventions

    if (!ok) {
        g_s2e->getDebugStream() << "S2ELUAExecutionState: could not write parameter " << param << ".\n";
    }

    return 0;
}

bool S2ELUAExecutionState::writeParameterCdecl(lua_State *L, uint32_t param, uint64_t val)
{
#if defined(TARGET_I386)
  target_ulong archval = (target_ulong) val;

  target_ulong sp = m_state->getSp() + (param + 1) * CPU_REG_SIZE;

#ifdef TARGET_X86_64
  if ((env->hflags & HF_CS64_MASK) && param > 5) {
      sp = m_state->getSp() + (param - 5) * CPU_REG_SIZE;
  }
  if ((env->hflags & HF_CS64_MASK) && param < 6) {
      unsigned int offset = 0;
      switch (param) {
      default:
      case 0: offset = CPU_OFFSET(regs[R_EDI]); break;
      case 1: offset = CPU_OFFSET(regs[R_ESI]); break;
      case 2: offset = CPU_OFFSET(regs[R_EDX]); break;
      case 3: offset = CPU_OFFSET(regs[R_ECX]); break;
      case 4: offset = CPU_OFFSET(regs[8]);     break;
      case 5: offset = CPU_OFFSET(regs[9]);     break;
      }

      m_state->writeCpuRegisterConcrete(offset, &archval, sizeof(archval));
      return true;
  } else
#endif /* TARGET_X86_64 */
      return m_state->writeMemoryConcrete(sp, &archval, sizeof(archval));
#endif
  return false;
}

bool S2ELUAExecutionState::writeParameterAAPCS(lua_State *L, uint32_t param, uint64_t val)
{
#ifdef TARGET_ARM
    target_ulong archval = (target_ulong) val;
    if (param <= 3) {
        m_state->writeCpuRegisterConcrete(CPU_OFFSET(regs[param]), &archval, sizeof(archval));
        return true;
    }
#endif
    return false;
}
int S2ELUAExecutionState::readMemorySymb(lua_State *L) {
	try {
		uint32_t address = luaL_checkint(L, 1);
		uint32_t type = 4;
		if (lua_isnumber(L, 2)) {
			type = luaL_checkint(L, 2);
		}
		klee::ref<klee::Expr> symValue;
		if (type == 4) {
			symValue = m_state->readMemory(address, klee::Expr::Int32);
		} else if (type == 1) {
			symValue = m_state->readMemory(address, klee::Expr::Int8);
		} else if (type == 2) {
			symValue = m_state->readMemory(address, klee::Expr::Int16);
		} else {
			symValue = klee::ref<klee::Expr>(0);
		}
		if (symValue.isNull()) {
			lua_pushstring(L, "error");
		} else {
			std::string expstr;
			llvm::raw_string_ostream exps(expstr);
			exps << symValue;
			lua_pushstring(L, exps.str().c_str());
		}
	} catch (...) {
		lua_pushstring(L, "error");
		return 1;
	}
	return 1;
}
int S2ELUAExecutionState::setExecuteStartAndEnd(lua_State *L){
	uint32_t startaddress = luaL_checkint(L, 1);
	uint32_t endaddress = luaL_checkint(L, 2);
	try{
		g_s2e->setExecuteWatchStart(startaddress);
		g_s2e->setExecuteWatchEnd(endaddress);
	}catch(...){
		return -1;
	}
	return 0;
}
int S2ELUAExecutionState::setMainProcess(lua_State *L){
	//uint64_t pid = luaL_checkint(L, 1);
	try{
//		setMainmoduleIndentity
//		g_s2e->setMainmoduleIndentity(pid);
	}catch(...){
		return -1;
	}
	return 0;
}

int S2ELUAExecutionState::getExecuteStartAndEnd(lua_State *L){
	uint64_t startaddress = 0;
	uint64_t endaddress = 0;
	try{
		startaddress  = g_s2e->getExecuteWatchStart();
		endaddress = g_s2e->getExecuteWatchEnd();
	}catch(...){
		return -1;
	}
	lua_pushnumber(L, startaddress);
	lua_pushnumber(L, endaddress);
	return 2;
}
int S2ELUAExecutionState::getTranslateStartAndEnd(lua_State *L){
	uint32_t startaddress = 0;
	uint32_t endaddress = 0;
	try{
		startaddress = g_s2e->getTranslateWatchStart();
		endaddress = g_s2e->getTranslateWatchEnd();
	}catch(...){
		return -1;
	}
	lua_pushnumber(L, startaddress);
	lua_pushnumber(L, endaddress);
	return 2;
}
int S2ELUAExecutionState::setTranslateStartAndEnd(lua_State *L){
	uint32_t startaddress = luaL_checkint(L, 1);
	uint32_t endaddress = luaL_checkint(L, 2);
	try{
		g_s2e->setTranslateWatchStart(startaddress);
		g_s2e->setTranslateWatchEnd(endaddress);
	}catch(...){
		return -1;
	}
	return 0;
}
int S2ELUAExecutionState::dumpInfo(lua_State *L){
	uint32_t infotype  = luaL_checkint(L, 1);
	//--0表示栈帧，1表示堆信息
	std::stringstream ss;
	std::stringstream sss;
	if(infotype == 0){
		s2e::plugins::StackMonitor *m_stackMonitor = static_cast<s2e::plugins::StackMonitor*>(g_s2e->getPlugin("StackMonitor"));
		if(m_stackMonitor){
			sss <<  m_stackMonitor->dump(m_state,ss).str();
			lua_pushstring(L, sss.str().c_str());
		}else{
			lua_pushstring(L, "");
		}
	}else if(infotype == 1){
			s2e::plugins::HeapMonitor *m_heapMonitor = static_cast<s2e::plugins::HeapMonitor*>(g_s2e->getPlugin("HeapMonitor"));
			if(m_heapMonitor){
				sss <<  m_heapMonitor->dump(m_state,ss).str();
				lua_pushstring(L, sss.str().c_str());
			}else{
				lua_pushstring(L, "");
			}
	}else{
		lua_pushstring(L, "");
	}
	return 1;
}
int S2ELUAExecutionState::searchMemory(lua_State *L) {
	uint32_t startaddress = luaL_checkint(L, 1);
	uint32_t endaddress = luaL_checkint(L, 2);
	std::string searchstr = luaL_checkstring(L, 3); //以十六进制表示的字符串 因此每两个一个字节 这个的长度一定是双数
	uint32_t searchresult = 0; //存放匹配到的第一个内存地址
	std::stringstream ss;
	uint32_t nextstart = startaddress;
	uint32_t datalength = searchstr.length() / 2;
	uint32_t ret;
	std::deque<uint32_t> searchdata; //deque
	for (uint32_t currentdataindex = 0; currentdataindex < datalength;
			++currentdataindex) {
		uint32_t currentdata=0;
		std::string high = searchstr.substr(currentdataindex * 2, 1);
		std::string low = searchstr.substr(currentdataindex * 2 + 1, 1);
		if (high == "0") {
			currentdata = 0;
			currentdata = currentdata << 4;
		} else if (high == "1") {
			currentdata = 1;
			currentdata = currentdata << 4;
		}else if (high == "2") {
			currentdata = 2;
			currentdata = currentdata << 4;
		}else if (high == "3") {
			currentdata = 3;
			currentdata = currentdata << 4;
		}else if (high == "4") {
			currentdata = 4;
			currentdata = currentdata << 4;
		}else if (high == "5") {
			currentdata = 5;
			currentdata = currentdata << 4;
		}else if (high == "6") {
			currentdata = 6;
			currentdata = currentdata << 4;
		}else if (high == "7") {
			currentdata = 7;
			currentdata = currentdata << 4;
		}else if (high == "8") {
			currentdata = 8;
			currentdata = currentdata << 4;
		}else if (high == "9") {
			currentdata = 9;
			currentdata = currentdata << 4;
		}else if (high == "A"|| high == "a") {
			currentdata = 10;
			currentdata = currentdata << 4;
		}else if (high == "B"|| high == "b") {
			currentdata = 11;
			currentdata = currentdata << 4;
		}else if (high == "C"|| high == "c") {
			currentdata = 12;
			currentdata = currentdata << 4;
		}else if (high == "D"|| high == "d") {
			currentdata = 13;
			currentdata = currentdata << 4;
		}else if (high == "E"|| high == "e") {
			currentdata = 14;
			currentdata = currentdata << 4;
		}else if (high == "F" || high == "f" ) {
			currentdata = 15;
			currentdata = currentdata << 4;
		}
		if (low == "0") {
			currentdata = currentdata + 0;
		} else if (low == "1") {
			currentdata = currentdata + 1;
		}else if (low == "2") {
			currentdata = currentdata + 2;
		}else if (low == "3") {
			currentdata = currentdata + 3;
		}else if (low == "4") {
			currentdata = currentdata + 4;
		}else if (low == "5") {
			currentdata = currentdata + 5;
		}else if (low == "6") {
			currentdata = currentdata + 6;
		}else if (low == "7") {
			currentdata = currentdata + 7;
		}else if (low == "8") {
			currentdata = currentdata + 8;
		}else if (low == "9") {
			currentdata = currentdata + 9;
		}else if (low == "A" || low == "a"  ) {
			currentdata = currentdata + 10;
		}else if (low == "B" || low == "b" ) {
			currentdata = currentdata + 11;
		}else if (low == "C" || low == "c" ) {
			currentdata = currentdata + 12;
		}else if (low == "D" || low == "d" ) {
			currentdata = currentdata + 13;
		}else if (low == "E" || low == "e" ) {
			currentdata = currentdata + 14;
		}else if (low == "F" || low == "f" ) {
			currentdata = currentdata + 15;
		}
		searchdata.push_back(currentdata);
	}
	try {
		do {
			bool found = true;
			if((nextstart % 0x10000)==0){
				g_s2e->getDebugStream() << "searchMemory: rangestart:"
							<< hexval(nextstart) << " rangeend:"<<hexval(nextstart+0x10000) <<"\n" ;
			}
			uint32_t comparestart = nextstart;
			for (uint32_t currentdataindex = 0; currentdataindex < datalength;
					++currentdataindex) {
				ret = 0;
				if (m_state->readMemoryConcrete(comparestart + currentdataindex,
						&ret, 1,S2EExecutionState::VirtualAddress)) {

						if (ret != searchdata.at(currentdataindex)) {
						found = false;
						nextstart = nextstart + 1;
						break;
					}
				} else {
					found = false;
					nextstart = nextstart + 1;
					break;
				}
			}
			if (found) {
				break;
			}
		} while (nextstart < endaddress);

		if (nextstart <= endaddress) {
			searchresult = nextstart;
		} else {
			searchresult = 0;
		}
		ss << hexval(searchresult);
		lua_pushstring(L, ss.str().c_str());
	} catch (...) {
		searchresult = -1;
		ss << hexval(searchresult);
		lua_pushstring(L, ss.str().c_str());
		return 1;
	}
	return 1;
}
int S2ELUAExecutionState::searchFirstSymMemory(lua_State *L) {
	uint32_t startaddress = luaL_checkint(L, 1);
	uint32_t endaddress = luaL_checkint(L, 2);
	uint32_t nextstart = startaddress;
	uint32_t searchresult = startaddress;
	std::stringstream ss;
	klee::ref<klee::Expr> symValue;
	try {
		do {
			bool found = false;
			if((nextstart % 0x10000)==0){
				g_s2e->getDebugStream() << "searchFirstSymMemory: rangestart:"
							<< hexval(nextstart) << " rangeend:"<<hexval(nextstart+0x10000) <<"\n" ;
			}
			try {
				symValue = m_state->readMemory(nextstart, klee::Expr::Int8);
				if (!symValue.isNull() && !isa < klee::ConstantExpr > (symValue)) {
					found = true;
				}
			} catch (...) {
			}
			if (found) {
				break;
			}
			nextstart = nextstart + 1;
		} while (nextstart < endaddress);

		if (nextstart <= endaddress) {
			searchresult = nextstart;
		} else {
			searchresult = 0;
		}
		ss << hexval(searchresult);
		lua_pushstring(L, ss.str().c_str());
	} catch (...) {
		return 1;
	}
	return 1;
}
int S2ELUAExecutionState::isForkingEnabled(lua_State *L) {
	lua_pushboolean(L, m_state->isForkingEnabled()); /* first result */
	return 1;
}
int S2ELUAExecutionState::isRunningConcrete(lua_State *L) {
	lua_pushboolean(L, m_state->isRunningConcrete()); /* first result */
	return 1;
}
int S2ELUAExecutionState::isSymbolicExecutionEnabled(lua_State *L) {
	lua_pushboolean(L, m_state->isSymbolicExecutionEnabled()); /* first result */
	return 1;
}
int S2ELUAExecutionState::getSp(lua_State *L) {
	lua_pushnumber(L, m_state->getSp()); /* first result */
	return 1;
}
int S2ELUAExecutionState::getDisasm(lua_State *L) {
	std::string regstr = luaL_checkstring(L, 1);
	uint32_t _size = luaL_checkint(L, 2);
	uint32_t _flag = luaL_checkint(L, 3);
	FILE *m_dissamfile;
	m_dissamfile = fopen(g_s2e->getOutputFilename(regstr).c_str(), "a+");
	if (!m_dissamfile) {
		perror(regstr.c_str());
	}
	target_disas(m_dissamfile, m_state->getPc(), _size, _flag);
	fclose(m_dissamfile);
	return 1;
}
int S2ELUAExecutionState::getFileName(lua_State *L) {
	std::string namestr = luaL_checkstring(L, 1);
	lua_pushstring(L, g_s2e->getOutputFilename(namestr).c_str());
	return 1;
}

int S2ELUAExecutionState::readMemory(lua_State *L)
{
    target_ulong address = luaL_checkint(L, 1);
    uint32_t size = luaL_checkint(L, 2);

    target_ulong ret;
    size = size <= 4 ? size : 4;
    size = size > sizeof (ret) ? sizeof (ret) : size;

    m_state->readMemoryConcrete(address, &ret, size);
    lua_pushnumber(L, ret);        /* first result */
    return 1;
}

int S2ELUAExecutionState::writeMemory(lua_State *L)
{
    target_ulong address = luaL_checkint(L, 1);
    uint32_t size = luaL_checkint(L, 2);
    target_ulong value = luaL_checkint(L, 3);

    if (size > sizeof(value)) {
        g_s2e->getDebugStream() << "writeMemory: size is too big" << hexval(size);
    } else if (!m_state->writeMemoryConcrete(address, &value, size)) {
        g_s2e->getDebugStream() << "writeMemory: Could not write to memory at address " << hexval(address);
    }

    return 0;
}

int S2ELUAExecutionState::writeMemorySymb(lua_State *L)
{
    std::string name = luaL_checkstring(L, 1);
    target_ulong address = luaL_checkint(L, 2);
    uint32_t size = luaL_checkint(L, 3);

    bool writeRange = false;
    uint32_t lowerBound = 0, upperBound = 0;
    if (lua_isnumber(L, 4) && lua_isnumber(L, 5)) {
        lowerBound = luaL_checkint(L, 4);
        upperBound = luaL_checkint(L, 5);
        writeRange = true;
    }

    g_s2e->getDebugStream() << "S2ELUAExecutionState: Writing symbolic value to memory location" <<
            " " << hexval(address) << " of size " << size << '\n';

    klee::Expr::Width bitLength=klee::Expr::Int8;
    switch(size) {
        case 1: bitLength = klee::Expr::Int8; break;
        case 2: bitLength = klee::Expr::Int16; break;
        case 4: bitLength = klee::Expr::Int32; break;
        case 8: bitLength = klee::Expr::Int64; break;
        default:
            {
                std::stringstream ss;
                ss << "writeMemorySymb: Invalid size " << size;
                lua_pushstring(L, ss.str().c_str());
                lua_error(L);
            }
            break;
    }

    // Read current memory content, check if already symbolic and use it in concolic mode
    target_ulong value = 0;
    std::vector<unsigned char> buf;
    if (!m_state->readMemoryConcrete(address, &value, size)) {
        g_s2e->getDebugStream() << "writeMemorySymb: Address " << hexval(address) << " already contains symbolic data, not overwriting.\n";
        return 0;
    }
    for (unsigned int i = 0; i < bitLength; i += 8) {
        buf.push_back(value & (0xFF << i));
    }

    klee::ref<klee::Expr> val = m_state->createConcolicValue(name, bitLength, buf);
    if (!m_state->writeMemory(address, val)) {
        std::stringstream ss;
        g_s2e->getDebugStream() << "writeMemorySymb: Could not write to memory at address " << hexval(address);
        return 0;
    }

    if (writeRange) {
        klee::ref<klee::Expr> val1 = klee::UleExpr::create(val, klee::ConstantExpr::create(upperBound,bitLength));
        klee::ref<klee::Expr> val2 = klee::NotExpr::create(klee::UltExpr::create(val, klee::ConstantExpr::create(lowerBound,bitLength)));
        klee::ref<klee::Expr> val3 = klee::AndExpr::create(val1, val2);
        g_s2e->getDebugStream() <<  "writeMemorySymb: " << val3 << '\n';
        m_state->addConstraint(val3);
    }

    return 0;
}

#ifdef TARGET_ARM
static bool RegNameToIndex(const std::string &regstr, uint32_t &regIndex, uint32 &size)
{
    if (regstr == "r0") {
        regIndex = 0;
        size = 4;
    }else if (regstr == "r1") {
        regIndex = 1;
        size = 4;
    }else if (regstr == "r2") {
        regIndex = 2;
        size = 4;
    }else if (regstr == "r3") {
        regIndex = 3;
        size = 4;
    }else if (regstr == "r4") {
        regIndex = 4;
        size = 4;
    }else if (regstr == "r5") {
        regIndex = 5;
        size = 4;
    }else if (regstr == "r6") {
        regIndex = 6;
        size = 4;
    }else if (regstr == "r7") {
        regIndex = 7;
        size = 4;
    }else if (regstr == "r8") {
        regIndex = 8;
        size = 4;
    }else if (regstr == "r9") {
        regIndex = 9;
        size = 4;
    }else if (regstr == "r10") {
        regIndex = 10;
        size = 4;
    }else if (regstr == "r11") {
        regIndex = 11;
        size = 4;
    }else if (regstr == "r12") {
        regIndex = 12;
        size = 4;
    }else if (regstr == "r13") {
        regIndex = 13;
        size = 4;
    }else if (regstr == "r14") {
        regIndex = 14;
        size = 4;
    }else if (regstr == "r15") {
        regIndex = 15;
        size = 4;
    }else if (regstr == "pc") {
        regIndex = 15;
        size = 4;
    }else if (regstr == "sp") {
        regIndex = 13;
        size = 4;
    }else if (regstr == "lr") { /* link register */
        regIndex = 14;
        size = 4;
    }else {
        return false;
    }
    return true;
}
#elif defined(TARGET_I386)
static bool RegNameToIndex(const std::string &regstr, uint32_t &regIndex, uint32 &size)
{
    if (regstr == "eax") {
        regIndex = R_EAX;
        size = CPU_REG_SIZE;
    }else if (regstr == "ebx") {
        regIndex = R_EBX;
        size = CPU_REG_SIZE;
    }else if (regstr == "ecx") {
        regIndex = R_ECX;
        size = CPU_REG_SIZE;
    }else if (regstr == "edx") {
        regIndex = R_EDX;
        size = CPU_REG_SIZE;
    }else if (regstr == "edi") {
        regIndex = R_EDI;
        size = CPU_REG_SIZE;
    }else if (regstr == "esi") {
        regIndex = R_ESI;
        size = CPU_REG_SIZE;
    }else if (regstr == "esp") {
        regIndex = R_ESP;
        size = CPU_REG_SIZE;
    }else if (regstr == "ebp") {
        regIndex = R_EBP;
        size = CPU_REG_SIZE;
    }else {
        return false;
    }
    return true;
}
#endif

int S2ELUAExecutionState::writeRegister(lua_State *L)
{
    std::string regstr = luaL_checkstring(L, 1);
    target_ulong value = luaL_checkint(L, 2);

    unsigned regIndex=0, size=0;

    g_s2e->getDebugStream() << "S2ELUAExecutionState: Writing to register "
            << regstr << " " << hexval(value) << '\n';

    if (!RegNameToIndex(regstr, regIndex, size)) {
        std::stringstream ss;
        ss << "Invalid register " << regstr;
        lua_pushstring(L, ss.str().c_str());
        lua_error(L);
    }

    if (CPU_REG_OFFSET(regIndex) < CPU_CONC_LIMIT) {
        m_state->writeCpuRegisterConcrete(CPU_REG_OFFSET(regIndex), &value, size);
    } else {
        // This alters execution, abort current instruction
        assert(CPU_REG_OFFSET(regIndex) == CPU_CONC_LIMIT);
        m_state->setPc(value);
        throw CpuExitException();
    }

    return 0;                   /* number of results */
}

int S2ELUAExecutionState::writeRegisterSymb(lua_State *L)
{
    uint64_t lowerBound;
    uint64_t upperBound;
    bool writeRange = false;
    std::string regstr = luaL_checkstring(L, 1);
    std::string namestr = luaL_checkstring(L, 2);

    if (lua_isnumber(L, 3) && lua_isnumber(L, 4)) {
        lowerBound = luaL_checkint(L, 3);
        upperBound = luaL_checkint(L, 4);
        writeRange = true;
    }

    unsigned regIndex=0, byteLength=0;

    g_s2e->getDebugStream() << "S2ELUAExecutionState: Writing to register "
            << regstr << '\n';

    if (!RegNameToIndex(regstr, regIndex, byteLength)) {
        std::stringstream ss;
        ss << "Invalid register " << regstr;
        lua_pushstring(L, ss.str().c_str());
        lua_error(L);
    }

    // Read current register content, check if already symbolic and optionally use it in concolic mode
    const klee::Expr::Width bitLength = byteLength << 3;
    target_ulong value = 0;
    klee::ref<klee::Expr> val;
    std::vector<unsigned char> buf;
    if (!m_state->readCpuRegisterConcrete(CPU_REG_OFFSET(regIndex), &value, byteLength)) {
        g_s2e->getDebugStream() << "writeRegisterSymb: register " << regstr << " already contains symbolic data, not overwriting.\n";
        return 0;
    }
    for (unsigned int i = 0; i < bitLength; i += 8) {
        buf.push_back(value & (0xFF << i));
    }

    val = m_state->createConcolicValue(namestr, bitLength, buf);
    m_state->writeCpuRegister(CPU_REG_OFFSET(regIndex), val);

    if (writeRange) {
        klee::ref<klee::Expr> val1 = klee::UleExpr::create(val, klee::ConstantExpr::create(upperBound,bitLength));
        klee::ref<klee::Expr> val2 = klee::NotExpr::create(klee::UltExpr::create(val, klee::ConstantExpr::create(lowerBound,bitLength)));
        klee::ref<klee::Expr> val3 = klee::AndExpr::create(val1, val2);
        g_s2e->getDebugStream() <<  "writeRegisterSymb: " << val3 << '\n';
        m_state->addConstraint(val3);
    }

    return 0;                   /* number of results */
}

int S2ELUAExecutionState::readRegister(lua_State *L)
{
    std::string regstr = luaL_checkstring(L, 1);

    unsigned regIndex=0, size=0;

    g_s2e->getDebugStream() << "S2ELUAExecutionState: Reading register "
            << regstr << '\n';

    if (!RegNameToIndex(regstr, regIndex, size)) {
        std::stringstream ss;
        ss << "Invalid register " << regstr;
        lua_pushstring(L, ss.str().c_str());
        lua_error(L);
    }

    target_ulong value = 0;

    if (CPU_REG_OFFSET(regIndex) < CPU_CONC_LIMIT) {
        klee::ref<klee::Expr> exprReg = m_state->readCpuRegister(CPU_REG_OFFSET(regIndex), klee::Expr::Width(size << 3));
        if (isa<klee::ConstantExpr>(exprReg)) {
            // Register is concrete, just read it
            value = cast<klee::ConstantExpr>(exprReg)->getZExtValue();
        }
        else
        {
            // Register is symbolic, get an example (without concretizing in-place)
            value = g_s2e->getExecutor()->toConstantSilent(*m_state, exprReg)->getZExtValue();
        }
    } else {
        assert(CPU_REG_OFFSET(regIndex) == CPU_CONC_LIMIT);
        value = (target_ulong) m_state->getPc();
    }


    lua_pushnumber(L, value);        /* first result */
    return 1;
}

int S2ELUAExecutionState::isSpeculative(lua_State *L)
{
    lua_pushboolean(L, m_state->isSpeculative());        /* first result */
    return 1;
}

int S2ELUAExecutionState::getID(lua_State *L)
{
    lua_pushnumber(L, m_state->getID());
    return 1;
}

///////////////////////////////////////////////////////
void ConfigFile::luaError(const char *fmt, ...)
{
    va_list v;
    va_start(v, fmt);

    if (g_s2e) {
        char str[512];
        vsnprintf(str, sizeof(str), fmt, v);
        g_s2e->getMessagesStream() << "ERROR: " << str << '\n';
    }else {
        vfprintf(stderr, fmt, v);
    }
    va_end(v);
    lua_close(m_luaState);
    exit(1);
}

void ConfigFile::luaWarning(const char *fmt, ...)
{
    va_list v;
    va_start(v, fmt);

    if (g_s2e) {
        char str[512];
        vsnprintf(str, sizeof(str), fmt, v);
        g_s2e->getWarningsStream() << "WARNING: " << str << '\n';
    }else {
        vfprintf(stderr, fmt, v);
    }
    va_end(v);
}

} // namespace s2e

