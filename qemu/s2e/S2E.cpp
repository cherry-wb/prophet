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

// XXX: qemu stuff should be included before anything from KLEE or LLVM !
extern "C" {
#include <qemu-common.h>
#include <cpus.h>
#include <main-loop.h>
#include <sysemu.h>
extern CPUArchState *env;
}

#include <tcg-llvm.h>

#include "S2E.h"

#include <s2e/Plugin.h>
#include <s2e/Plugins/CorePlugin.h>
#include <s2e/ConfigFile.h>
#include <s2e/Utils.h>
#include <s2e/S2EExecutor.h>
#include <s2e/S2EExecutionState.h>

#include <s2e/s2e_qemu.h>
#include <llvm/Support/FileSystem.h>
#include <llvm/Support/Path.h>
#include <llvm/Support/CommandLine.h>
#include <llvm/Support/raw_os_ostream.h>
#include <llvm/Support/raw_ostream.h>

#include <llvm/Module.h>
#include <llvm/ExecutionEngine/ExecutionEngine.h>
#include <llvm/Bitcode/ReaderWriter.h>


#include <klee/Interpreter.h>
#include <klee/Common.h>

#include <iostream>
#include <sstream>
#include <deque>
#include <stdlib.h>
#include <assert.h>
#include <errno.h>

#include <stdarg.h>
#include <stdio.h>

#include <sys/stat.h>

#ifndef _WIN32
#include <sys/types.h>
#include <unistd.h>
#endif

// stacktrace.h (c) 2008, Timo Bingmann from http://idlebox.net/
// published under the WTFPL v2.0
#if defined(CONFIG_WIN32)
void print_stacktrace(void)
{
    std::ostream &os = g_s2e->getDebugStream();
    os << "Stack trace printing unsupported on Windows" << '\n';
}
void s2e_unload_all_bundle(){
}
#else
#include <stdio.h>
#include <stdlib.h>
#include <execinfo.h>
#include <cxxabi.h>

/** Print a demangled stack backtrace of the caller function to FILE* out. */
void print_stacktrace(void)
{
    unsigned int max_frames = 63;
    llvm::raw_ostream &os = g_s2e->getDebugStream();
    os << "Stack trace" << '\n';

    // storage array for stack trace address data
    void* addrlist[max_frames+1];

    // retrieve current stack addresses
    int addrlen = backtrace(addrlist, sizeof(addrlist) / sizeof(void*));

    if (addrlen == 0) {
        s2e_debug_print("  <empty, possibly corrupt>\n");
        return;
    }

    // resolve addresses into strings containing "filename(function+address)",
    // this array must be free()-ed
    char** symbollist = backtrace_symbols(addrlist, addrlen);

    // allocate string which will be filled with the demangled function name
    size_t funcnamesize = 256;
    char* funcname = (char*)malloc(funcnamesize);

    // iterate over the returned symbol lines. skip the first, it is the
    // address of this function.
    for (int i = 1; i < addrlen; i++)
    {
        char *begin_name = 0, *begin_offset = 0, *end_offset = 0;

        // find parentheses and +address offset surrounding the mangled name:
        // ./module(function+0x15c) [0x8048a6d]
        for (char *p = symbollist[i]; *p; ++p)
        {
            if (*p == '(')
                begin_name = p;
            else if (*p == '+')
                begin_offset = p;
            else if (*p == ')' && begin_offset) {
                end_offset = p;
                break;
            }
        }

        if (begin_name && begin_offset && end_offset
            && begin_name < begin_offset)
        {
            *begin_name++ = '\0';
            *begin_offset++ = '\0';
            *end_offset = '\0';

            // mangled name is now in [begin_name, begin_offset) and caller
            // offset in [begin_offset, end_offset). now apply
            // __cxa_demangle():

            int status;
            char* ret = abi::__cxa_demangle(begin_name,
                                            funcname, &funcnamesize, &status);
            if (status == 0) {
                funcname = ret; // use possibly realloc()-ed string
                s2e_debug_print("  %s : %s+%s\n",
                        symbollist[i], funcname, begin_offset);
            }
            else {
                // demangling failed. Output function name as a C function with
                // no arguments.
                s2e_debug_print("  %s : %s()+%s\n",
                        symbollist[i], begin_name, begin_offset);
            }
        }
        else
        {
            // couldn't parse the line? print the whole line.
            s2e_debug_print("  %s\n", symbollist[i]);
        }
    }

    free(funcname);
    free(symbollist);
}
/*
 * bundle mechanism
 */
#include <s2e/bundle_mechanism.h>
#include <dlfcn.h>
BundleInfo dbaf_bundles[] ={
		{ NULL,NULL, "" },
	    { NULL,NULL, "" },
	    { NULL,NULL, "" },
	    { NULL,NULL, "" },
	    { NULL,NULL, "" },
	    { NULL,NULL, "" },
	    { NULL,NULL, "" },
	    { NULL,NULL, "" },
	    { NULL,NULL, "" },
	    { NULL,NULL, "" },
	    { NULL,NULL, "" },
	    { NULL,NULL, "" },
	    { NULL,NULL, "" },
	    { NULL,NULL, "" },
	    { NULL,NULL, "" },
	    { NULL,NULL, "" },
	    { NULL,NULL, "" },
	    { NULL,NULL, "" },
	    { NULL,NULL, "" },
	    { NULL,NULL, "" },
	};

int dbaf_bundles_size =  sizeof(dbaf_bundles) / sizeof(BundleInfo);
void s2e_load_bundle(const char *plugin_path){
	bundle_interface_t *(*init_bundle)(void);
	char *error;
	BundleInfo* load_bundle = NULL;
	int loaded = 0;
	//先比较是否已经加载
	uint32_t bundlesize=0;
	int counter = 0;
	bundlesize = sizeof(dbaf_bundles) / sizeof(BundleInfo);
	for (counter = 0; counter < bundlesize; counter++) {
		if(strcmp(dbaf_bundles[counter].bundle_path, plugin_path) == 0){
			fprintf(stderr, "%s has already been loaded! \n", plugin_path);
			loaded = 1;
		}
	}
	if(loaded == 0){
		for (counter = 0; counter < bundlesize; counter++) {
			if (dbaf_bundles[counter].handle == NULL ) {
				load_bundle = &(dbaf_bundles[counter]);
				break;
			}
		}
		load_bundle->handle = dlopen(plugin_path, RTLD_NOW);
		if (NULL == load_bundle->handle) {
			char tempbuf[128];
			strncpy(tempbuf, dlerror(), 127);
			fprintf(stderr,  "%s\n", tempbuf);
			fprintf(stderr,  "%s COULD NOT BE LOADED - ERR = [%s]\n", plugin_path,
					tempbuf);
			return;
		}
		dlerror();
		init_bundle = (bundle_interface_t *(*)())dlsym(load_bundle->handle, "init_bundle");
		if ((error = dlerror()) != NULL ) {
			fprintf(stderr, "%s\n", error);
			dlclose(load_bundle->handle);
			load_bundle->handle = NULL;
			load_bundle->bundle_path[0] = '\0';
			return;
		}

		load_bundle->bundle = init_bundle();

		if (NULL == load_bundle->bundle) {
			fprintf(stderr,  "fail to initialize the bundle!\n");
			dlclose(load_bundle->handle);
			load_bundle->handle = NULL;
			load_bundle->bundle = NULL;
			load_bundle->bundle_path[0] = '\0';
			return;
		}
		strncpy(load_bundle->bundle_path, plugin_path, PATH_MAX);
		fprintf(stderr,  "%s is loaded successfully!\n", plugin_path);
	}
}
void s2e_unload_bundle(const char *plugin_path){
	BundleInfo* load_bundle = NULL;
	int loaded = 0;
	uint32_t bundlesize=0;
	int counter = 0;
	bundlesize = sizeof(dbaf_bundles) / sizeof(BundleInfo);
	for (counter = 0; counter < bundlesize; counter++) {
		if(strcmp(dbaf_bundles[counter].bundle_path, plugin_path) == 0){
			loaded = 1;
			load_bundle = &(dbaf_bundles[counter]);
		}
	}
	if(loaded == 1){
		if(load_bundle->bundle)
			load_bundle->bundle->bundle_cleanup();
		if(load_bundle->handle)
			dlclose(load_bundle->handle);
		load_bundle->handle = NULL;
		load_bundle->bundle = NULL;

		monitor_printf(default_mon, "%s is unloaded!\n", load_bundle->bundle_path);
		load_bundle->bundle_path[0] = '\0';

	}else{
		monitor_printf(default_mon, "%s is not loaded!\n", plugin_path);
	}
	return;
}
void s2e_unload_all_bundle(){
	uint32_t bundlesize=0;
	int counter = 0;
	bundlesize = sizeof(dbaf_bundles) / sizeof(BundleInfo);
	for (counter = 0; counter < bundlesize; counter++) {
		if(strlen(dbaf_bundles[counter].bundle_path)>5)
			s2e_unload_bundle(dbaf_bundles[counter].bundle_path);
	}
	return;
}
#endif //CONFIG_WIN32

namespace s2e {

using namespace std;


S2E::S2E(int argc, char** argv, TCGLLVMContext *tcgLLVMContext,
    const std::string &configFileName, const std::string &outputDirectory,
    const std::string &nodetype, const std::string &nodeid,int verbose, unsigned s2e_max_processes)
        : m_tcgLLVMContext(tcgLLVMContext)
{
    if (s2e_max_processes < 1) {
        std::cerr << "You must at least allow one process for S2E." << '\n';
        exit(1);
    }

    if (s2e_max_processes > S2E_MAX_PROCESSES) {
        std::cerr << "S2E can handle at most " << S2E_MAX_PROCESSES << " processes." << '\n';
        std::cerr << "Please increase the S2E_MAX_PROCESSES constant." << '\n';
        exit(1);
    }

#ifdef CONFIG_WIN32
    if (s2e_max_processes > 1) {
        std::cerr << "S2E for Windows does not support more than one process" << '\n';
        exit(1);
    }
#endif

    m_startTimeSeconds = llvm::sys::TimeValue::now().seconds();

    m_forking = false;
    m_node_type = nodetype;
    m_node_id = nodeid;

    m_maxProcesses = s2e_max_processes;
    m_currentProcessIndex = 0;
    m_currentProcessId = 0;
    m_plugininied = false;
    m_TranslateWatchStart = (uint64_t)-1;
    m_ExecuteWatchStart =  (uint64_t)-1;
    m_TranslateWatchEnd = (uint64_t)-1;
    m_ExecuteWatchEnd =  (uint64_t)-1;

    S2EShared *shared = m_sync.acquire();
    shared->currentProcessCount = 1;
    shared->lastStateId = 0;
    shared->lastFileId = 1;
    shared->processIds[m_currentProcessId] = m_currentProcessIndex;
    shared->processPids[m_currentProcessId] = getpid();
    m_sync.release();

    /* Parse configuration file */
    m_configFile = new s2e::ConfigFile(configFileName);

    /* Open output directory. Do it at the very beginning so that
       other init* functions can use it. */
    initOutputDirectory(outputDirectory, verbose, false);

    /* Copy the config file into the output directory */
    {
        llvm::raw_ostream *out = openOutputFile("s2e.config.lua");
        ifstream in(configFileName.c_str());
        char c;
        while (in.get(c)) {
            (*out) << c;
        }
        delete out;
    }

    /* Save command line arguments */
    {
        llvm::raw_ostream *out = openOutputFile("s2e.cmdline");
        for(int i = 0; i < argc; ++i) {
			if(i != 0)
			{
				(*out) << " ";
				m_cmdline << " ";
			}
			std::string arg = std::string (argv[i]);

			if(arg.find(std::string("s2e-node-id"))!= std::string::npos){
				++i;// 跳过s2e-node-id参数
			}else if(arg.find(std::string("gnome-terminal"))!= std::string::npos){
				++i;
			}else{
				(*out) << "'" << argv[i] << "'";
				 m_cmdline << "'" << argv[i] << "'";
			}
        }
        delete out;
    }


    /* Initialize KLEE command line options */
    initKleeOptions();

    /* Initialize S2EExecutor */
    initExecutor();

    /* Load and initialize plugins */
    initPlugins();

    /* Init the custom memory allocator */
    //void slab_init();
    //slab_init();
}

void S2E::writeBitCodeToFile()
{
    std::string error;
    std::string fileName = getOutputFilename("module.bc");
    llvm::raw_fd_ostream o(fileName.c_str(), error, llvm::raw_fd_ostream::F_Binary);

    llvm::Module *module = m_tcgLLVMContext->getModule();

    // Output the bitcode file to stdout
    llvm::WriteBitcodeToFile(module, o);
}

S2E::~S2E()
{
    //Delete all the stuff used by the instance
    foreach(Plugin* p, m_activePluginsList)
        delete p;

    //Tell other instances we are dead so they can fork more
    S2EShared *shared = m_sync.acquire();

    assert(shared->processIds[m_currentProcessId] == m_currentProcessIndex);
    shared->processIds[m_currentProcessId] = (unsigned) -1;
    shared->processPids[m_currentProcessId] = (unsigned) -1;
    --shared->currentProcessCount;

    m_sync.release();

    delete m_pluginsFactory;
    writeBitCodeToFile();

    // KModule wants to delete the llvm::Module in destroyer.
    // llvm::ModuleProvider wants to delete it too. We have to arbitrate.
    //XXX: llvm 3.0. How does it work?
    //m_tcgLLVMContext->getModuleProvider()->releaseModule();

    //Make sure everything is clean
    m_s2eExecutor->flushTb();

    //This is necessary, as the execution engine uses the module.
    m_tcgLLVMContext->deleteExecutionEngine();

    delete m_s2eExecutor;
    delete m_s2eHandler;

    //The execution engine deletion will also delete the module.
    m_tcgLLVMContext->deleteExecutionEngine();

    delete m_configFile;

    delete m_warningStream;
    delete m_messageStream;

    delete m_infoFileRaw;
    delete m_warningsFileRaw;
    delete m_messagesFileRaw;
    delete m_debugFileRaw;
}

Plugin* S2E::getPlugin(const std::string& name) const
{
    ActivePluginsMap::const_iterator it = m_activePluginsMap.find(name);
    if(it != m_activePluginsMap.end())
        return const_cast<Plugin*>(it->second);
    else
        return NULL;
}

std::string S2E::getOutputFilename(const std::string &fileName)
{
    llvm::sys::Path filePath(m_outputDirectory);
    filePath.appendComponent(fileName);
    return filePath.str();
}

llvm::raw_ostream* S2E::openOutputFile(const std::string &fileName)
{
    std::string path = getOutputFilename(fileName);
    std::string error;
    llvm::raw_fd_ostream *f = new llvm::raw_fd_ostream(path.c_str(), error, llvm::raw_fd_ostream::F_Binary);

    if (!f || error.size()>0) {
        llvm::errs() << "Error opening " << path << ": " << error << "\n";
        exit(-1);
    }

    return f;
}

void S2E::initOutputDirectory(const string& outputDirectory, int verbose, bool forked)
{
		//可以在系统暂停时，将未完成状态序列化保存到文件（定义一个约定的共享文件）
		//下次启动时自动，在config中加载上次未完成的任务
		std::string outputfolderid = m_configFile->getString("pluginsConfig.currentNodeID");
	    m_TranslateWatchStart =m_configFile->getInt("pluginsConfig.translateWatchStart",(uint64_t)-1);
	    m_ExecuteWatchStart =m_configFile->getInt("pluginsConfig.executeWatchStart",(uint64_t)-1);
	    m_TranslateWatchEnd =m_configFile->getInt("pluginsConfig.translateWatchEnd",(uint64_t)-1);
	    m_ExecuteWatchEnd =m_configFile->getInt("pluginsConfig.executeWatchEnd",(uint64_t)-1);
	    if(m_node_id.length()>0){
			outputfolderid = m_node_id;
		}
    if (!forked) {
        //In case we create the first S2E process
        if (outputDirectory.empty()) {
            llvm::sys::Path cwd = llvm::sys::Path::GetCurrentDirectory();

            for (int i = 0; ; i++) {
                ostringstream dirName;
                dirName << "s2e-out-" <<outputfolderid<<"-"<< i;

                llvm::sys::Path dirPath(cwd);
                dirPath.appendComponent(dirName.str());

                bool exists = false;
                llvm::sys::fs::exists(dirPath.str(), exists);

                if(!exists) {
                    m_outputDirectory = dirPath.str();
                    break;
                }
            }

        } else {
            m_outputDirectory = outputDirectory;
        }
        m_outputDirectoryBase = m_outputDirectory;
    }else {
        m_outputDirectory = m_outputDirectoryBase;
    }


#ifndef _WIN32
    if (m_maxProcesses > 1) {
        // Create one output directory per child process.
        // This prevents child processes from clobbering each other's output.
        llvm::sys::Path dirPath(m_outputDirectory);

        ostringstream oss;
        oss << m_currentProcessIndex;

        dirPath.appendComponent(oss.str());
        bool exists = false;
        llvm::sys::fs::exists(dirPath.str(), exists);

        assert(!exists);
        m_outputDirectory = dirPath.str();
    }
#endif

    std::cout << "S2E: output directory = \"" << m_outputDirectory << "\"\n";

    llvm::sys::Path outDir(m_outputDirectory);
    std::string mkdirError;
    //检测共享目录是否存在，不存在就创建一个，否则跳过 //cherry 取m_outputDirectory的字串，剔除（-i）
    m_shareDirectory = m_outputDirectory.substr(0,m_outputDirectory.find_last_of('-'));
    llvm::sys::Path shareDir(m_shareDirectory);
    std::string mksharedirError;
#ifdef _WIN32
    if (shareDir.createDirectoryOnDisk(false, &mksharedirError)) {
#else
    if (shareDir.createDirectoryOnDisk(true, &mksharedirError)) {
#endif
        std::cerr << "Could not create share directory " << shareDir.str() <<
                " error: " << mksharedirError << '\n';
    }
#ifdef _WIN32
    //XXX: If set to true on Windows, it fails when parent directories exist
    //For now, we assume that only the last component needs to be created
    if (outDir.createDirectoryOnDisk(false, &mkdirError)) {
#else
    if (outDir.createDirectoryOnDisk(true, &mkdirError)) {
#endif
        std::cerr << "Could not create output directory " << outDir.str() <<
                " error: " << mkdirError << '\n';
        exit(-1);
    }

#ifndef _WIN32
    if (!forked) {
        llvm::sys::Path s2eLast(".");
        s2eLast.appendComponent("s2e-last");

        if ((unlink(s2eLast.c_str()) < 0) && (errno != ENOENT)) {
            perror("ERROR: Cannot unlink s2e-last");
            exit(1);
        }

        if (symlink(m_outputDirectoryBase.c_str(), s2eLast.c_str()) < 0) {
            perror("ERROR: Cannot make symlink s2e-last");
            exit(1);
        }
    }
#endif

    ios_base::sync_with_stdio(true);
    cout.setf(ios_base::unitbuf);
    cerr.setf(ios_base::unitbuf);

    m_infoFileRaw = openOutputFile("info.txt");
    m_debugFileRaw = openOutputFile("debug.txt");
    m_messagesFileRaw = openOutputFile("messages.txt");
    m_warningsFileRaw = openOutputFile("warnings.txt");

    // Messages appear in messages.txt, debug.txt and on stdout
    raw_tee_ostream *messageStream = new raw_tee_ostream(m_messagesFileRaw);
    messageStream->addParentBuf(m_debugFileRaw);
    if (verbose) {
        messageStream->addParentBuf(&llvm::outs());
    }
    m_messageStream = messageStream;

    // Warnings appear in warnings.txt, messages.txt, debug.txt
    // and on stderr in red color
    raw_tee_ostream *warningsStream = new raw_tee_ostream(m_warningsFileRaw);
    warningsStream->addParentBuf(m_debugFileRaw);
    warningsStream->addParentBuf(m_messagesFileRaw);
    warningsStream->addParentBuf(new raw_highlight_ostream(&llvm::errs()));
    m_warningStream = warningsStream;


#if 0
    // Messages appear in messages.txt, debug.txt and on stdout
    m_messagesStreamBuf = new TeeStreamBuf(messagesFileBuf);
    static_cast<TeeStreamBuf*>(m_messagesStreamBuf)->addParentBuf(debugFileBuf);
    if(verbose)
        static_cast<TeeStreamBuf*>(m_messagesStreamBuf)->addParentBuf(cerr.rdbuf());
    m_messagesFile->rdbuf(m_messagesStreamBuf);
    m_messagesFile->setf(ios_base::unitbuf);

    // Warnings appear in warnings.txt, messages.txt, debug.txt
    // and on stderr in red color
    m_warningsStreamBuf = new TeeStreamBuf(warningsFileBuf);
    static_cast<TeeStreamBuf*>(m_warningsStreamBuf)->addParentBuf(messagesFileBuf);
    static_cast<TeeStreamBuf*>(m_warningsStreamBuf)->addParentBuf(debugFileBuf);
    if(verbose)
        static_cast<TeeStreamBuf*>(m_warningsStreamBuf)->addParentBuf(
                          new HighlightStreamBuf(cerr.rdbuf()));
    else
        static_cast<TeeStreamBuf*>(m_warningsStreamBuf)->addParentBuf(cerr.rdbuf());
    m_warningsFile->rdbuf(m_warningsStreamBuf);
    m_warningsFile->setf(ios_base::unitbuf);
#endif

    klee::klee_message_stream = m_messageStream;
    klee::klee_warning_stream = m_warningStream;
}

void S2E::initKleeOptions()
{
    std::vector<std::string> kleeOptions = getConfig()->getStringList("s2e.kleeArgs");
    if(!kleeOptions.empty()) {
        int numArgs = kleeOptions.size() + 1;
        const char **kleeArgv = new const char*[numArgs + 1];

        kleeArgv[0] = "s2e.kleeArgs";
        kleeArgv[numArgs] = 0;

        for(unsigned int i = 0; i < kleeOptions.size(); ++i)
            kleeArgv[i+1] = kleeOptions[i].c_str();

        llvm::cl::ParseCommandLineOptions(numArgs, (char**) kleeArgv);

        delete[] kleeArgv;
    }
}

void S2E::initPlugins()
{
    m_pluginsFactory = new PluginsFactory();

    m_corePlugin = dynamic_cast<CorePlugin*>(
            m_pluginsFactory->createPlugin(this, "CorePlugin"));
    assert(m_corePlugin);

    m_activePluginsList.push_back(m_corePlugin);
    m_activePluginsMap.insert(
            make_pair(m_corePlugin->getPluginInfo()->name, m_corePlugin));
    if(!m_corePlugin->getPluginInfo()->functionName.empty())
        m_activePluginsMap.insert(
            make_pair(m_corePlugin->getPluginInfo()->functionName, m_corePlugin));

    vector<string> pluginNames = getConfig()->getStringList("plugins");
    /* bundle mechanism*/
		foreach(const string& pluginName, pluginNames) {
			 string pathkey("pluginsConfig."+pluginName+".so_path");
			 string so_path = getConfig()->getString(pathkey,"");
			 if(so_path.length() > 2){//加载进内存，如果一个多个插件放在一个so中，则只加载进内存一次
				s2e_load_bundle(so_path.c_str());
			 }
		}
		m_pluginsFactory->refresh();
     /* bundle mechanism*/
    /* Check and load plugins */
    foreach(const string& pluginName, pluginNames) {
        const PluginInfo* pluginInfo = m_pluginsFactory->getPluginInfo(pluginName);
        if(!pluginInfo) {
            std::cerr << "ERROR: plugin '" << pluginName
                      << "' does not exist in this S2E installation" << '\n';
            s2e_unload_all_bundle();
            exit(1);
        } else if(getPlugin(pluginInfo->name)) {
            std::cerr << "ERROR: plugin '" << pluginInfo->name
                      << "' was already loaded "
                      << "(is it enabled multiple times ?)" << '\n';
            s2e_unload_all_bundle();
            exit(1);
        } else if(!pluginInfo->functionName.empty() &&
                    getPlugin(pluginInfo->functionName)) {
            std::cerr << "ERROR: plugin '" << pluginInfo->name
                      << "' with function '" << pluginInfo->functionName
                      << "' can not be loaded because" << '\n'
                      <<  "    this function is already provided by '"
                      << getPlugin(pluginInfo->functionName)->getPluginInfo()->name
                      << "' plugin" << '\n';
            s2e_unload_all_bundle();
            exit(1);
        } else {
            Plugin* plugin = m_pluginsFactory->createPlugin(this, pluginName);
            assert(plugin);

            m_activePluginsList.push_back(plugin);
            m_activePluginsMap.insert(
                    make_pair(plugin->getPluginInfo()->name, plugin));
            if(!plugin->getPluginInfo()->functionName.empty())
                m_activePluginsMap.insert(
                    make_pair(plugin->getPluginInfo()->functionName, plugin));
        }
    }

    /* Check dependencies */
    foreach(Plugin* p, m_activePluginsList) {
        foreach(const string& name, p->getPluginInfo()->dependencies) {
            if(!getPlugin(name)) {
                std::cerr << "ERROR: plugin '" << p->getPluginInfo()->name
                          << "' depends on plugin '" << name
                          << "' which is not enabled in config" << '\n';
                exit(1);
            }
        }
    }

    /* Initialize plugins */
    foreach(Plugin* p, m_activePluginsList) {
        p->initialize();
    }
    m_plugininied = true;
}

void S2E::initExecutor()
{
    m_s2eHandler = new S2EHandler(this);
    S2EExecutor::InterpreterOptions IOpts;
    m_s2eExecutor = new S2EExecutor(this, m_tcgLLVMContext, IOpts, m_s2eHandler);
}

llvm::raw_ostream& S2E::getStream(llvm::raw_ostream &stream,
                             const S2EExecutionState* state) const
{
    fflush(stdout);
    fflush(stderr);

    stream.flush();

    if(state) {
        llvm::sys::TimeValue curTime = llvm::sys::TimeValue::now();
        stream << (curTime.seconds() - m_startTimeSeconds) << ' ';

        if (m_maxProcesses > 1) {
            stream  << "[Node " << m_currentProcessIndex <<
                    "/" << m_currentProcessId << " - State " << state->getID() << "] ";
        }else {
            stream << "[State " << state->getID() << "] ";
        }
    }
    return stream;
}

void S2E::printf(llvm::raw_ostream &os, const char *fmt, ...)
{
    va_list vl;
    va_start(vl,fmt);

    char str[512];
    vsnprintf(str, sizeof(str), fmt, vl);
    os << str;
}

void S2E::refreshPlugins()
{
    foreach2(it, m_activePluginsList.begin(), m_activePluginsList.end()) {
        (*it)->refresh();
    }
}

int S2E::fork()
{
#ifdef CONFIG_WIN32
    return -1;
#else

    S2EShared *shared = m_sync.acquire();
    if (shared->currentProcessCount == m_maxProcesses) {
        m_sync.release();
        return -1;
    }

    unsigned newProcessIndex = shared->lastFileId;
    ++shared->lastFileId;
    ++shared->currentProcessCount;

    m_sync.release();

    pid_t pid = ::fork();
    if (pid < 0) {
        //Fork failed

        shared = m_sync.acquire();
        //Do not decrement lastFileId, as other fork may have
        //succeeded while we were handling the failure.

        --shared->currentProcessCount;
        m_sync.release();
        return -1;
    }

    if (pid == 0) {
        //Allocate a free slot in the instance map
        shared = m_sync.acquire();
        unsigned i=0;
        for (i=0; i<m_maxProcesses; ++i) {
            if (shared->processIds[i] == (unsigned)-1) {
                shared->processIds[i] = newProcessIndex;
                shared->processPids[i] = getpid();
                m_currentProcessId = i;
                break;
            }
        }
        assert (i < m_maxProcesses);
        m_sync.release();

        m_currentProcessIndex = newProcessIndex;
        //We are the child process, setup the log files again
        initOutputDirectory(m_outputDirectoryBase, 0, true);
        //Also recreate new statistics files
        m_s2eExecutor->initializeStatistics();
        //And the solver output
        m_s2eExecutor->initializeSolver();

        m_forking = true;

        qemu_init_cpu_loop();
        if (main_loop_init()) {
            fprintf(stderr, "qemu_init_main_loop failed\n");
            exit(1);
        }

        if (init_timer_alarm(0)<0) {
            getDebugStream() << "Could not initialize timers" << '\n';
            exit(-1);
        }

        qemu_init_vcpu(env);
        cpu_synchronize_all_post_init();
        os_setup_signal_handling();
        vm_start();
        os_setup_post();
        resume_all_vcpus();
        vm_stop(RUN_STATE_SAVE_VM);

        m_forking = false;
    }

    return pid == 0 ? 1 : 0;
#endif
}

unsigned S2E::fetchAndIncrementStateId()
{
    S2EShared *shared = m_sync.acquire();
    unsigned ret = shared->lastStateId;
    ++shared->lastStateId;
    m_sync.release();
    return ret;
}
unsigned S2E::fetchNextStateId()
{
    S2EShared *shared = m_sync.acquire();
    unsigned ret = shared->lastStateId;
    m_sync.release();
    return ret;
}

unsigned S2E::getCurrentProcessCount()
{
    S2EShared *shared = m_sync.acquire();
    unsigned ret = shared->currentProcessCount;
    m_sync.release();
    return ret;
}

unsigned S2E::getProcessIndexForId(unsigned id)
{
    assert(id < m_maxProcesses);
    S2EShared *shared = m_sync.acquire();
    unsigned ret = shared->processIds[id];
    m_sync.release();
    return ret;
}

bool S2E::checkDeadProcesses()
{
    S2EShared *shared = m_sync.acquire();
    bool ret = false;
    for (unsigned i=0; i<m_maxProcesses; ++i) {
        if (shared->processPids[i] == (unsigned)-1) {
            continue;
        }

        //Check if pid is alive
        char buffer[64];
        snprintf(buffer, sizeof(buffer), "kill -0 %d", shared->processPids[i]);
        int ret = system(buffer);
        if (ret != 0) {
            //Process is dead, we have to decrement everything
            shared->processIds[i] = (unsigned) -1;
            shared->processPids[i] = (unsigned) -1;
            --shared->currentProcessCount;
            ret = true;
        }
    }

    m_sync.release();
    return ret;
}

} // namespace s2e

/******************************/
/* Functions called from QEMU */

extern "C" {

S2E* g_s2e = NULL;

S2E* s2e_initialize(int argc, char** argv,
            TCGLLVMContext* tcgLLVMContext,
            const char* s2e_config_file,  const char* s2e_output_dir,
            int verbose, unsigned s2e_max_processes,const char *s2e_node_type,const char *s2e_node_id)
{
    return new S2E(argc, argv, tcgLLVMContext,
                   s2e_config_file ? s2e_config_file : "",
                   s2e_output_dir  ? s2e_output_dir  : "",
                   s2e_node_type ? s2e_node_type : "master",s2e_node_id?s2e_node_id:"", verbose, s2e_max_processes);
}

void s2e_close(S2E *s2e)
{
    print_stacktrace();

    delete s2e;
    tcg_llvm_close(tcg_llvm_ctx);
    tcg_llvm_ctx = NULL;
	s2e_unload_all_bundle();
}

int s2e_is_forking()
{
    return g_s2e->isForking();
}

void s2e_debug_print(const char *fmtstr, ...)
{
    if (!g_s2e) {
        return;
    }

    va_list vl;
    va_start(vl,fmtstr);

    char str[512];
    vsnprintf(str, sizeof(str), fmtstr, vl);
    g_s2e->getDebugStream() << str;

    va_end(vl);
}

void s2e_warning_print(const char *fmtstr, ...)
{
    if (!g_s2e) {
        return;
    }

    va_list vl;
    va_start(vl,fmtstr);

    char str[512];
    vsnprintf(str, sizeof(str), fmtstr, vl);
    g_s2e->getWarningsStream() << str;

    va_end(vl);
}

//Print a klee expression.
//Useful for invocations from GDB
void s2e_print_expr(void *expr);
void s2e_print_expr(void *expr) {
    klee::ref<klee::Expr> e = *(klee::ref<klee::Expr>*)expr;
    std::stringstream ss;
    ss << e;
    g_s2e->getDebugStream() << ss.str() << '\n';
}

void s2e_print_value(void *value);
void s2e_print_value(void *value) {
    llvm::Value *v = (llvm::Value*)value;
    g_s2e->getDebugStream() << *v << '\n';
}

extern "C"
{
void s2e_execute_cmd(const char *cmd)
{
    g_s2e->getConfig()->invokeLuaCommand(cmd);
}

//Non-S2E modules can redeclare this variable with __attribute__((weak))
//to check whether they run in S2E or not.
int g_s2e_linked = 1;

}


} // extern "C"
