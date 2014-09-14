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

#ifndef S2E__HeapMonitor_H
#define S2E__HeapMonitor_H

#include <s2e/Plugin.h>
#include <s2e/Plugins/CorePlugin.h>
#include <s2e/S2EExecutionState.h>
#include <fstream>
#include <set>

#include <s2e/Plugins/ModuleExecutionDetector.h>
#include <s2e/Plugins/ExecutionTracers/ExecutionTracer.h>
#include <s2e/Plugins/OSMonitor.h>

namespace s2e {
namespace plugins {

struct HeapBlockInfo {
	//////////////////////////堆块指针的前八个字节
    uint64_t selfsize;//2字节
    uint64_t presize;//2字节
    uint64_t segindex;//1字节
    uint64_t flags;//1字节
    uint64_t unusedbytes;//1字节
    uint64_t tagindex;//1字节
    ///////////////////////////
    uint64_t blockaddress;//堆块内存区域指针(从数据区域开始，不包括头结构)
    bool isinfreelist;
	friend llvm::raw_ostream& operator<<(llvm::raw_ostream &os,
			const HeapBlockInfo &heapBlockInfo);
	friend std::stringstream& operator<<(std::stringstream &os,
			const HeapBlockInfo &heapBlockInfo);
};
 class HeapMonitor : public Plugin
{
    S2E_PLUGIN
public:
    HeapMonitor(S2E* s2e);
	std::string m_mainmodule;
	uint64_t m_mainmodulePid;
public:
    virtual void HeapCreate(S2EExecutionState* state,uint32_t hreturn, uint32_t flOptions, uint32_t dwInitialSize, uint32_t dwMaximumSize) ;
    virtual void HeapDestroy(S2EExecutionState* state,uint32_t hHeap) ;
    virtual void HeapReAlloc(S2EExecutionState* state,uint32_t hreturn, uint32_t hHeap, uint32_t dwFlags,uint32_t lpMem,uint32_t dwBytes) ;
    virtual void HeapAlloc(S2EExecutionState* state,uint32_t hreturn, uint32_t hHeap, uint32_t dwFlags,uint32_t dwBytes) ;
    virtual void HeapFree(S2EExecutionState* state,uint32_t hHeap,uint32_t dwFlags,uint32_t lpMem) ;
	/**
	 * 根据放存地址，如果在堆块上就返回true和对应的堆块信息info，否则返回false
	 */
    virtual bool getHeapBlockInfo(S2EExecutionState *state, uint64_t accessaddress, HeapBlockInfo &info) const ;
    /**
     * 查看已维护的堆块信息
     */
    virtual void dump(S2EExecutionState *state) ;
    virtual std::stringstream& dump(S2EExecutionState *state,std::stringstream &os,bool issimplify=false) ;

    /**
	 * Emitted when a new heap is Creat
	 */
	sigc::signal<void, S2EExecutionState*> onHeapCreation;

	/**
	 * Emitted when a heap is freed.
	 */
	sigc::signal<void, S2EExecutionState*> onHeapFree;

	/**
	 * Emitted when a new heapBlock is alloc
	 */
	sigc::signal<void, S2EExecutionState*> onHeapBlockCreation;

	/**
	 * Emitted when a heapBlock is freed.
	 */
	sigc::signal<void, S2EExecutionState*> onHeapBlockFree;

};


} // namespace plugins
} // namespace s2e

#endif // S2E_HeapMonitor_H
