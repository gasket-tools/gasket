#include <dlfcn.h>
#include <napi.h>
#include <iostream>
#include <v8.h>
#include <v8-profiler.h>
#include <string>

#include <regex>
#include <vector>
#include <sstream>
#include <iomanip>

using v8::Isolate;
using v8::Object;
using v8::Local;
using v8::Value;
using v8::HeapProfiler;
using v8::HeapSnapshot;
using v8::HeapGraphNode;

typedef uint32_t SnapshotObjectId;

typedef std::string (*PrintObjectFn)(void*);


PrintObjectFn print_fn;

typedef struct {
      const size_t _staticArgCount = 6;
      napi_env _env;
      napi_callback_info _info;
      napi_value _this;
      size_t _argc;
      napi_value* _argv;
      napi_value _staticArgs[6]{};
      napi_value* _dynamicArgs;
      void* _data;
} CallbackInfoPublic;


void* extract_sfi_pointer(const std::string& input) {
    std::regex pattern(R"(shared_info:\s*0x([0-9a-fA-F]+))");
    std::smatch match;

    if (std::regex_search(input, match, pattern) && match.size() > 1) {
        std::string hex_str = match[1].str();
        std::uintptr_t address = std::stoull(hex_str, nullptr, 16);
        return reinterpret_cast<void*>(address);
    }

    return nullptr; // Not found
}


void* extract_fti_pointer(const std::string& input) {
    std::regex pattern(R"(function_data:\s*0x([0-9a-fA-F]+)\s<FunctionTemplateInfo)");
    std::smatch match;

    if (std::regex_search(input, match, pattern) && match.size() > 1) {
        std::string hex_str = match[1].str();
        std::uintptr_t address = std::stoull(hex_str, nullptr, 16);
        return reinterpret_cast<void*>(address);
    }

    return nullptr; // Not found
}

std::vector<std::string> extract_foreign_data_addresses(const std::vector<void*>& overloads) {
  std::vector<std::string> results;
  std::regex address_regex(R"(foreign address\s*:\s*(0x[0-9a-fA-F]+))");

  for (void* ptr : overloads) {
    std::string output = print_fn(ptr);

    std::smatch match;
    if (std::regex_search(output, match, address_regex)) {
      results.push_back(match[1].str());
    } else {
      results.push_back("UNKNOWN");
    }
  }

  return results;
}

std::string extract_callback_and_overloads_json(const std::string& input) {
    std::string callback = "NONE";
    std::vector<void*> overloads;

	// std::cout << "FTI string: " << input << std::endl;

    // Match callback
    std::regex callback_regex(R"(___CALLBACK___(.*?)___CALLBACK___)");
    std::smatch callback_match;
    if (std::regex_search(input, callback_match, callback_regex)) {
        callback = callback_match[1].str();
    }

    // Match overload block and extract addresses
    std::regex overload_block_regex(R"(___OVERLOADS___([\s\S]*?)___OVERLOADS___)");
    std::smatch overload_block_match;
    if (std::regex_search(input, overload_block_match, overload_block_regex)) {
        std::string block = overload_block_match[1].str();
  	    // std::cout << "overloads block: " << block << std::endl;

        std::regex addr_regex(R"(0x[0-9a-fA-F]+)");
        auto begin = std::sregex_iterator(block.begin(), block.end(), addr_regex);
        auto end = std::sregex_iterator();

        for (auto it = begin; it != end; ++it) {
		    std::string addr_str = it->str();
        	void* ptr = reinterpret_cast<void*>(std::stoull(addr_str, nullptr, 16));
            overloads.push_back(ptr);
        }
    }

    std::vector<std::string> overload_funcs;
	overload_funcs = extract_foreign_data_addresses(overloads);

    // Construct JSON string manually
    std::ostringstream oss;
    oss << "{\n";
    oss << "  \"callback\": \"" << callback << "\",\n";
    oss << "  \"overloads\": [";
    for (size_t i = 0; i < overload_funcs.size(); ++i) {
        oss << "\"" << overload_funcs[i] << "\"";
        if (i < overload_funcs.size() - 1) oss << ", ";
    }
    oss << "]\n}";
    return oss.str();
}


Napi::Value getcb(const Napi::CallbackInfo& info) {
	Napi::Env env = info.Env();
	std::string msg;
    void *jsfunc_addr;
    void *sfi_addr;
    void *fti_addr;

    // void *address;
    auto new_info = (CallbackInfoPublic&)(info);
	auto x = *(new_info._argv);
	jsfunc_addr = *(void **)x;


    // void* handle = dlopen(NULL, RTLD_LAZY);

    // if (!print_fn)
	// 	print_fn = (PrintObjectFn)dlsym(handle, "_Z35_v8_internal_Print_Object_To_StringPv");

    // if (info.Length() < 1) {
	// 	Napi::TypeError::New(env, "Expected 1 argument").ThrowAsJavaScriptException();
	// 	return env.Null();
	// }

    // if (!info[0]->IsObject()) {
	// 	Napi::TypeError::New(env, "Not an object").ThrowAsJavaScriptException();
	// 	return env.Null();
    // }

    std::cout << "JSFUNC address: " << jsfunc_addr << std::endl;

    // jsfunc_addr = *(void**)address;
    // bool sane = ((((uintptr_t)jsfunc_addr >> 47) + 1) & ~1ULL) == 0;
    // // bool sane = (((jsfunc_addr >> 47) + 1) & ~1ULL) == 0;
    // if (!sane)
    //     std::cout << "JSFUNC ADDRESS INSANE" << jsfunc_addr << std::endl;


    // if (!jsfunc_addr || !sane)
    //     goto out_with_null;

    msg = print_fn(jsfunc_addr);

    sfi_addr = extract_sfi_pointer(msg);

    if (!sfi_addr)
        goto out_with_null;

    msg = print_fn(sfi_addr);

    fti_addr = extract_fti_pointer(msg);

    if (!fti_addr)
        goto out_with_null;

    msg = print_fn(fti_addr);

    msg = extract_callback_and_overloads_json(msg);

    goto out;

out_with_null:
    msg = "NONE";
	return Napi::String::New(env, msg);
out:
  return Napi::String::New(env, msg);
}

Napi::Value job_addr(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    if (info.Length() < 1 || !info[0].IsNumber()) {
        Napi::TypeError::New(env, "Expected a number").ThrowAsJavaScriptException();
        return env.Null();
    }

    // Extract the 64-bit integer argument
    uint64_t raw = info[0].As<Napi::Number>().Int64Value();

    // Convert to pointer
    void* address = reinterpret_cast<void*>(static_cast<uintptr_t>(raw));

    // Call your internal helper
    std::string msg = print_fn(address);

    // Return JS string
    return Napi::String::New(env, msg);
}


Napi::Value jid2(const Napi::CallbackInfo& info) {
	Napi::Env env = info.Env();
	std::string ret;
    void *y;
    auto new_info = (CallbackInfoPublic&)(info);
	auto x = *(new_info._argv);

	y = *(void **)x;
    ret = std::to_string(reinterpret_cast<uintptr_t>(y));

	return Napi::String::New(env, ret);
}

Napi::Value get_objects(const Napi::CallbackInfo& info) {
	Napi::Env env = info.Env();
	Isolate* isolate = Isolate::GetCurrent();
	void *addr;
	void *jsfunc_addr;

	std::string msg;
    HeapProfiler* hp = isolate->GetHeapProfiler();
    const HeapSnapshot* snap = hp->TakeHeapSnapshot();

    std::vector<Local<Object>> locals;

    int total = snap->GetNodesCount();
    for (int i = 0; i < total; i++) {
        const HeapGraphNode* node = snap->GetNode(i);
        if (node->GetType() != HeapGraphNode::kObject) continue;

        SnapshotObjectId id = node->GetId();
        Local<Value> val = hp->FindObjectById(id);
        locals.push_back(val.As<Object>());

        printf("Progress: %d / %d nodes processed\n", i, total);
    }

    // final message
    printf("Done: processed %d nodes\n", total);

//     for (int i = 0; i < snap->GetNodesCount(); i++) {
//       const HeapGraphNode* node = snap->GetNode(i);
//       if (node->GetType() != HeapGraphNode::kObject) continue;
// 
//       SnapshotObjectId id = node->GetId();
// 
//       Local<Value> val = hp->FindObjectById(id);
//       locals.push_back(val.As<Object>());
//     }

    std::vector<void *> addresses;
    for (auto obj : locals) {
		addr = *obj;
		if (!addr)
			continue;
		jsfunc_addr = *(void**)addr;
		if (!jsfunc_addr)
			continue;
		addresses.push_back(jsfunc_addr);
    }

    std::ostringstream oss;
    oss << "[";
    for (size_t i = 0; i < addresses.size(); i++) {
      if (i > 0) oss << ",";
      oss << "\"0x"
          << std::hex << std::setw(sizeof(void*) * 2)
          << std::setfill('0')
          << reinterpret_cast<uintptr_t>(addresses[i])
          << "\"";
    }
    oss << "]";

    msg = oss.str();
    const_cast<HeapSnapshot*>(snap)->Delete();
	return Napi::String::New(env, msg);
}

Napi::Object Init(Napi::Env env, Napi::Object exports) {
  void* handle = dlopen(NULL, RTLD_LAZY);
  if (!print_fn)
      print_fn = (PrintObjectFn)dlsym(handle, "_Z35_v8_internal_Print_Object_To_StringPv");
  exports.Set("id", Napi::Function::New(env, jid2));
  exports.Set("getcb", Napi::Function::New(env, getcb));
  exports.Set("get_objects", Napi::Function::New(env, get_objects));
  exports.Set("job_addr", Napi::Function::New(env, job_addr));
  return exports;
}

NODE_API_MODULE(native, Init)

