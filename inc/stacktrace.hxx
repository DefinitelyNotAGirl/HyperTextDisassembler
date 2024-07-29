#pragma once

#include <string>
#include <iostream>
#include <vector>

struct TraceInfo {
    std::string file;
    int line;
    std::string function;
};

#if defined(platform_linux)
	#include <backtrace.h>
	#include <execinfo.h>
	#include <unistd.h>
	#include <cxxabi.h> // For __cxa_demangle
	static void error_callback(void *data, const char *msg, int errnum) {
	    std::cerr << "Error: " << msg << " (errnum " << errnum << ")\n";
	}
	
	static void syminfo_callback(void *data, uintptr_t pc, const char *symname, uintptr_t symval, uintptr_t symsize) {
	    TraceInfo *info = reinterpret_cast<TraceInfo*>(data);
	    if (symname) {
	        int status;
	        char *demangled = abi::__cxa_demangle(symname, nullptr, nullptr, &status);
	        if (status == 0) {
	            info->function = demangled;
	            free(demangled);
	        } else {
	            // Demangling failed, use the original symbol name
	            info->function = symname;
	        }
	    }
	}
	
	static int full_callback(void *data, uintptr_t pc, const char *filename, int lineno, const char *function) {
	    auto trace_info = reinterpret_cast<std::vector<TraceInfo>*>(data);
	    TraceInfo info;
	    if (filename) {
	        info.file = filename;
	        info.line = lineno;
	    }
	    if (function) {
	        int status;
	        char *demangled = abi::__cxa_demangle(function, nullptr, nullptr, &status);
	        if (status == 0) {
	            info.function = demangled;
	            free(demangled);
	        } else {
	            // Demangling failed, use the original function name
	            info.function = function;
	        }
	    }
	    trace_info->push_back(info);
	    return 0;
	}
	
	static std::string get_source_info(void *addr) {
	    backtrace_state *state = backtrace_create_state(nullptr, 1, error_callback, nullptr);
	    if (!state) {
	        return "Failed to create backtrace state.";
	    }
	
	    std::vector<TraceInfo> trace_info;
	    backtrace_pcinfo(state, reinterpret_cast<uintptr_t>(addr), full_callback, error_callback, &trace_info);
	    if (trace_info.empty()) {
	        return "No source info available.";
	    }
	
	    const TraceInfo &info = trace_info.front();
	    std::string result;
	    if (!info.file.empty()) {
	        result += info.file + ":" + std::to_string(info.line);
	    }
	    if (!info.function.empty()) {
	        result += " in " + info.function;
	    }
	    return result;
	}
	
	inline void printStacktrace(uint64_t len)
	{
		void** array = (void**)calloc(len,8);
		size_t size = backtrace(array, len);
		std::cerr << "stack trace: ";
		for(uint64_t I = 1;I<size;I++)
		{
			std::string info = get_source_info(array[I]);
			if(!info.empty())std::cerr << "\n" << info;
		}
		std::cerr << std::endl;
	}
#elif defined(platform_apple)
	#include <execinfo.h>
	#include <unistd.h>
	#include <cxxabi.h> // For __cxa_demangle
	#include <dlfcn.h>  // For dladdr
	static std::string demangle(const char* mangledName) {
	    int status;
	    char* demangled = abi::__cxa_demangle(mangledName, nullptr, nullptr, &status);
	    std::string result = (status == 0) ? demangled : mangledName;
	    free(demangled);
	    return result;
	}

	static std::string get_source_info(void* addr) {
	    Dl_info info;
	    if (dladdr(addr, &info) && info.dli_sname) {
	        std::string function = demangle(info.dli_sname);
	        std::string file = (info.dli_fname) ? info.dli_fname : "unknown";
	        return file + " in " + function;
	    }
	    return "No source info available.";
	}

	static void printStacktrace(uint64_t len) {
	    void** array = (void**)calloc(len, sizeof(void*));
	    size_t size = backtrace(array, len);
	    char** symbols = backtrace_symbols(array, size);

	    std::cerr << "stack trace:";
	    for (size_t i = 1; i < size; ++i) {
	        std::string info = get_source_info(array[i]);
	        if (!info.empty()) {
	            std::cerr << "\n" << info;
	        }
	    }
	    std::cerr << std::endl;

	    free(symbols);
	    free(array);
	}
#else
	std::string get_source_info(void* addr);
	void printStacktrace(uint64_t len);
#endif
