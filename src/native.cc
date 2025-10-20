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

class CallbackBundle {
 public:
  static v8::Local<v8::Value> New(napi_env env, napi_callback cb, void* data);
  static CallbackBundle* FromCallbackData(v8::Local<v8::Value> data);

  napi_env env;
  void* cb_data;
  napi_callback cb;

 private:
  static void Delete(napi_env env, void* data, void* hint);
};

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

std::string extract_callback(const std::string& input) {
    std::string callback = "NONE";
    std::regex callback_regex(R"(-\s*callback:\s*(0x[0-9a-fA-F]+))");
    std::smatch callback_match;
    if (std::regex_search(input, callback_match, callback_regex)) {
        callback = callback_match[1].str();
    }
    return callback;
}

std::vector<std::string> extract_overloads_from_fti(const std::string& input) {
    std::vector<std::string> overload_funcs;
    std::vector<void*> overloads;
    std::regex pattern(R"(-\s*rare_data:\s*(0x[0-9a-fA-F]+))");
    std::smatch match;
    std::string raw;
    std::uintptr_t address;
    void *rare_data_addr = NULL;
    void* c_function_overloads_addr = NULL;
    if (std::regex_search(input, match, pattern) && match.size() > 1) {
        std::string hex_str = match[1].str();
        address = std::stoull(hex_str, nullptr, 16);
        rare_data_addr = reinterpret_cast<void*>(address);
    }

    if (!rare_data_addr)
        return overload_funcs;
    raw = print_fn(rare_data_addr);

    std::regex pattern_2(R"(-\s*c_function_overloads:\s*(0x[0-9a-fA-F]+))");

    if (std::regex_search(raw, match, pattern_2) && match.size() > 1) {
        std::string hex_str = match[1].str();
        address = std::stoull(hex_str, nullptr, 16);
        c_function_overloads_addr = reinterpret_cast<void*>(address);
    }
    if (!c_function_overloads_addr) {
        return overload_funcs;
    }
    raw = print_fn(c_function_overloads_addr);
    std::regex pattern_3(R"(\s*\d+:\s*(0x[0-9a-fA-F]+)\s*<Foreign>)");

    auto begin = std::sregex_iterator(raw.begin(), raw.end(), pattern_3);
    auto end   = std::sregex_iterator();

    for (auto it = begin; it != end; ++it) {
        std::string hex_str = (*it)[1].str();
        address = std::stoull(hex_str, nullptr, 16);
        void* ptr = reinterpret_cast<void*>(address);
        overloads.push_back(ptr);
    }
    if (overloads.empty())
        return overload_funcs;

    overload_funcs = extract_foreign_data_addresses(overloads);
    return overload_funcs;
}

std::string extract_callback_and_overloads_json(const std::string& input) {

    std::string callback;
    callback = extract_callback(input);

    std::vector<std::string> overload_funcs;
    overload_funcs = extract_overloads_from_fti(input);

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
    void *sfi_addr;
    void *fti_addr;

    if (info.Length() < 1 || !info[0].IsNumber()) {
        Napi::TypeError::New(env, "Expected a number").ThrowAsJavaScriptException();
        return env.Null();
    }

    // Extract the 64-bit integer argument
    uint64_t raw = info[0].As<Napi::Number>().Int64Value();

    // Convert to pointer
    void* jsfunc_addr = reinterpret_cast<void*>(static_cast<uintptr_t>(raw));

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

    bool sane = ((((uintptr_t)address >> 47) + 1) & ~1ULL) == 0;
    std::string msg;
    if (sane)
        msg = print_fn(address);
    else
        msg = "INVALID_ADDRESS";

    // Return JS string
    return Napi::String::New(env, msg);
}

void* extract_callback_data_from_sfi(const std::string& input) {
    std::regex data_regex(R"(data=\s*0x([0-9a-fA-F]+))");
    std::smatch match;

    if (std::regex_search(input, match, data_regex)) {
        std::string hex_str = match[1].str();
        std::uintptr_t address = std::stoull(hex_str, nullptr, 16);
        return reinterpret_cast<void*>(address);
    }

    return nullptr;
}

void* extract_external_value_from_js_external_object(const std::string& input) {
    std::regex value_regex(R"(external value:\s*0x([0-9a-fA-F]+))");
    std::smatch match;

    if (std::regex_search(input, match, value_regex)) {
        std::string hex_str = match[1].str();
        std::uintptr_t address = std::stoull(hex_str, nullptr, 16);
        return reinterpret_cast<void*>(address);
    }

    return nullptr;
}

Napi::Value extract_fcb_invoke(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    if (info.Length() < 1 || !info[0].IsNumber()) {
        Napi::TypeError::New(env, "Expected a number").ThrowAsJavaScriptException();
        return env.Null();
    }

    // Extract the 64-bit integer argument
    uint64_t raw = info[0].As<Napi::Number>().Int64Value();
    // Convert to pointer
    void* jsfunc_addr = reinterpret_cast<void*>(static_cast<uintptr_t>(raw));

    void *sfi_addr;
    void *callback_data_addr;
    void *external_value_addr;
    void *cfunc_addr;
    CallbackBundle bundle;
    std::string msg;

    if (!jsfunc_addr)
        goto out_with_null;

    msg = print_fn(jsfunc_addr);
    sfi_addr = extract_sfi_pointer(msg);

    if (!sfi_addr)
        goto out_with_null;

    // job SFI
    msg = print_fn(sfi_addr);
    // Get callback data from job SFI
    callback_data_addr = extract_callback_data_from_sfi(msg);

    if (!callback_data_addr)
        goto out_with_null;

    // job callback_data
    msg = print_fn(callback_data_addr);

    external_value_addr = extract_external_value_from_js_external_object(msg);

    if (!external_value_addr)
        goto out_with_null;

    bundle = *(CallbackBundle *)external_value_addr;
    cfunc_addr = (void *)bundle.cb;
    msg = std::to_string(reinterpret_cast<uintptr_t>(cfunc_addr));
    goto out;

out_with_null:
    msg = "NONE";
out:
    return Napi::String::New(env, msg);
}

Napi::Value extract_napi(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    if (info.Length() < 1 || !info[0].IsNumber()) {
        Napi::TypeError::New(env, "Expected a number").ThrowAsJavaScriptException();
        return env.Null();
    }

    // Extract the 64-bit integer argument
    uint64_t raw = info[0].As<Napi::Number>().Int64Value();
    // Convert to pointer
    void* jsfunc_addr = reinterpret_cast<void*>(static_cast<uintptr_t>(raw));
    void *sfi_addr;
    void *callback_data_addr;
    void *external_value_addr;
    void *cfunc_addr;
    CallbackBundle bundle;
    // Napi_CallbackData napi_cb_data;
    void **napi_cb_data;
    std::string msg;

    if (!jsfunc_addr)
        goto out_with_null;

    // job JSFunction
    msg = print_fn(jsfunc_addr);
    sfi_addr = extract_sfi_pointer(msg);

    if (!sfi_addr)
        goto out_with_null;

    // job SFI
    msg = print_fn(sfi_addr);
    // Get callback data from job SFI.
    callback_data_addr = extract_callback_data_from_sfi(msg);

    if (!callback_data_addr)
        goto out_with_null;

    // job callback_data
    msg = print_fn(callback_data_addr);

    external_value_addr = extract_external_value_from_js_external_object(msg);

    if (!external_value_addr)
        goto out_with_null;

    bundle = *(CallbackBundle *)external_value_addr;
    napi_cb_data = (void **)bundle.cb_data;
    cfunc_addr = *napi_cb_data;
    msg = std::to_string(reinterpret_cast<uintptr_t>(cfunc_addr));
    goto out;

out_with_null:
    msg = "NONE";
out:
    return Napi::String::New(env, msg);
}

void* extract_js_external_object_from_api_object(const std::string& input) {
    std::regex callback_regex(R"(0x[0-9a-fA-F]+(?=\s+<JSExternalObject>))");
    std::smatch callback_match;
    if (std::regex_search(input, callback_match, callback_regex)) {
        std::string hex_str = callback_match[0].str();
        std::uintptr_t address = std::stoull(hex_str, nullptr, 16);
        return reinterpret_cast<void*>(address);
    }

    return nullptr;
}

Napi::Value extract_nan(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    if (info.Length() < 1 || !info[0].IsNumber()) {
        Napi::TypeError::New(env, "Expected a number").ThrowAsJavaScriptException();
        return env.Null();
    }

    // Extract the 64-bit integer argument
    uint64_t raw = info[0].As<Napi::Number>().Int64Value();
    // Convert to pointer
    void* jsfunc_addr = reinterpret_cast<void*>(static_cast<uintptr_t>(raw));
    void *sfi_addr;
    void *callback_data_addr;
    void *external_value_addr;
    void *cfunc_addr;
    void *js_external_object_addr;
    std::string msg;

    if (!jsfunc_addr)
        goto out_with_null;

    // job JSFunction
    msg = print_fn(jsfunc_addr);

    sfi_addr = extract_sfi_pointer(msg);

    if (!sfi_addr)
        goto out_with_null;

    // job SFI
    msg = print_fn(sfi_addr);

    // Get callback data from job SFI.
    callback_data_addr = extract_callback_data_from_sfi(msg);

    if (!callback_data_addr)
        goto out_with_null;

    // job callback_data = [api object]
    msg = print_fn(callback_data_addr);
    js_external_object_addr = extract_js_external_object_from_api_object(msg);

    if (!js_external_object_addr)
        goto out_with_null;

    // Extract External Value from external object
    msg = print_fn(js_external_object_addr);
    external_value_addr = extract_external_value_from_js_external_object(msg);

    if (!external_value_addr)
        goto out_with_null;

    // cfuncaddr == external value addr
    cfunc_addr = external_value_addr;
    msg = std::to_string(reinterpret_cast<uintptr_t>(cfunc_addr));
    goto out;
out_with_null:
    msg = "NONE";
out:
    return Napi::String::New(env, msg);
}

std::string extract_name_from_jsfunction(const std::string& input) {
    std::regex name_regex(R"(-\s*name:\s*(.+))");
    std::smatch match;

    if (std::regex_search(input, match, name_regex)) {
        return match[1].str();
    }

    return "NONE";
}

Napi::Value extract_neon(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    if (info.Length() < 1 || !info[0].IsNumber()) {
        Napi::TypeError::New(env, "Expected a number").ThrowAsJavaScriptException();
        return env.Null();
    }

    // Extract the 64-bit integer argument
    uint64_t raw = info[0].As<Napi::Number>().Int64Value();
    // Convert to pointer
    void* jsfunc_addr = reinterpret_cast<void*>(static_cast<uintptr_t>(raw));
    std::string msg;

    if (!jsfunc_addr)
        goto out_with_null;

	// job JSFunction
    msg = print_fn(jsfunc_addr);

    msg = extract_name_from_jsfunction(msg);

	goto out;
out_with_null:
    msg = "NONE";
out:
    return Napi::String::New(env, msg);
}

Napi::Value extract_cfunc_getset(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    if (info.Length() < 1 || !info[0].IsNumber()) {
        Napi::TypeError::New(env, "Expected a number").ThrowAsJavaScriptException();
        return env.Null();
    }

    // Extract the 64-bit integer argument
    uint64_t raw = info[0].As<Napi::Number>().Int64Value();
    // Convert to pointer
    void* callback_data_addr = reinterpret_cast<void*>(static_cast<uintptr_t>(raw));

	void *external_value_addr;
	void *cfunc_addr;
	CallbackBundle bundle;
	void **napi_cb_data;
    std::string msg;


    msg = print_fn(callback_data_addr);

    external_value_addr = extract_external_value_from_js_external_object(msg);

	if (!external_value_addr)
		goto out_with_null;

	bundle = *(CallbackBundle *)external_value_addr;
	napi_cb_data = (void **)bundle.cb_data;
	cfunc_addr = *napi_cb_data;
    msg = std::to_string(reinterpret_cast<uintptr_t>(cfunc_addr));

    goto out;

out_with_null:
    msg = "NONE";
out:
    return Napi::String::New(env, msg);
}

Napi::Value jid(const Napi::CallbackInfo& info) {
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
    
        // --- progress bar ---
        int width = 50;  // bar width
        float progress = (float)(i + 1) / total;
        int pos = (int)(width * progress);
    
        printf("\r[");
        for (int j = 0; j < width; j++) {
            if (j < pos) printf("=");
            else if (j == pos) printf(">");
            else printf(" ");
        }
        printf("] %3d%% (%d/%d)", (int)(progress * 100), i + 1, total);
        fflush(stdout);
    }
    printf("\n");

    // final message
    printf("Done: processed %d nodes\n", total);

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
  // Fallback, cxx11 ABI
  if (!print_fn)
      print_fn = (PrintObjectFn)dlsym(handle, "_Z35_v8_internal_Print_Object_To_StringB5cxx11Pv");
  exports.Set("jid", Napi::Function::New(env, jid));
  exports.Set("getcb", Napi::Function::New(env, getcb));
  exports.Set("get_objects", Napi::Function::New(env, get_objects));
  exports.Set("job_addr", Napi::Function::New(env, job_addr));
  exports.Set("extract_fcb_invoke", Napi::Function::New(env, extract_fcb_invoke));
  exports.Set("extract_napi", Napi::Function::New(env, extract_napi));
  exports.Set("extract_nan", Napi::Function::New(env, extract_nan));
  exports.Set("extract_neon", Napi::Function::New(env, extract_neon));
  exports.Set("extract_cfunc_getset", Napi::Function::New(env, extract_cfunc_getset));
  return exports;
}

NODE_API_MODULE(native, Init)
