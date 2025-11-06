/*
 * LIEF PE Binary Binding
 *
 * Provides PE-specific binary manipulation for Windows executables
 */

#include "binary.h"
#include "optional_header.h"
#include "section.h"

namespace node_lief {

// Static storage for PE Binary constructor
static Napi::FunctionReference* pe_binary_constructor = nullptr;

Napi::Object PEBinary::Init(Napi::Env env, Napi::Object exports) {
  Napi::Function constructor = DefineClass(env, "Binary", {
    // Abstract properties
    InstanceAccessor<&PEBinary::GetFormat>("format"),
    InstanceAccessor<&PEBinary::GetEntrypoint>("entrypoint"),
    InstanceAccessor<&PEBinary::GetIsPie>("isPie"),
    InstanceAccessor<&PEBinary::GetHasNx>("hasNx"),
    InstanceAccessor<&PEBinary::GetHeader>("header"),
    // PE-specific properties
    InstanceAccessor<&PEBinary::GetOptionalHeader>("optionalHeader"),
    // Abstract methods
    InstanceMethod<&PEBinary::GetSections>("sections"),
    InstanceMethod<&PEBinary::GetSymbols>("symbols"),
    InstanceMethod<&PEBinary::GetRelocations>("relocations"),
    InstanceMethod<&PEBinary::GetSegments>("segments"),
    InstanceMethod<&PEBinary::GetSymbol>("getSymbol"),
    InstanceMethod<&PEBinary::PatchAddress>("patchAddress"),
    InstanceMethod<&PEBinary::Write>("write"),
    // PE-specific methods (camelCase)
    InstanceMethod<&PEBinary::GetSection>("getSection"),
  });

  pe_binary_constructor = new Napi::FunctionReference();
  *pe_binary_constructor = Napi::Persistent(constructor);

  exports.Set("Binary", constructor);
  return exports;
}

Napi::Value PEBinary::NewInstance(Napi::Env env, std::unique_ptr<LIEF::PE::Binary> binary) {
  if (!pe_binary_constructor) {
    Napi::Error::New(env, "PEBinary constructor not initialized").ThrowAsJavaScriptException();
    return env.Null();
  }
  Napi::Object obj = pe_binary_constructor->New({});
  PEBinary* wrapper = PEBinary::Unwrap(obj);
  wrapper->pe_binary_ = std::move(binary);
  wrapper->binary_ = wrapper->pe_binary_.get();
  return obj;
}

PEBinary::PEBinary(const Napi::CallbackInfo& info)
    : Napi::ObjectWrap<PEBinary>(info), BinaryImpl() {
  Napi::Env env = info.Env();

  // Allow construction with no arguments for NewInstance pattern
  if (info.Length() == 0) {
    return;
  }

  if (info.Length() < 1 || !info[0].IsString()) {
    Napi::TypeError::New(env, "PEBinary constructor requires a string file path").ThrowAsJavaScriptException();
    return;
  }

  std::string filename = info[0].As<Napi::String>();

  // Parse the binary file
  auto parsed = LIEF::PE::Parser::parse(filename);
  if (!parsed) {
    Napi::Error::New(env, "Failed to parse PE binary file").ThrowAsJavaScriptException();
    return;
  }

  pe_binary_ = std::move(parsed);
  binary_ = pe_binary_.get();
}

Napi::Value PEBinary::GetSections(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();

  if (!pe_binary_) {
    return env.Null();
  }

  Napi::Array sections_array = Napi::Array::New(env);
  uint32_t idx = 0;

  for (auto& section : pe_binary_->sections()) {
    sections_array[idx++] = PESection::NewInstance(env, &section);
  }

  return sections_array;
}

Napi::Value PEBinary::GetSection(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();

  if (!pe_binary_ || info.Length() < 1 || !info[0].IsString()) {
    return env.Null();
  }

  std::string section_name = info[0].As<Napi::String>();
  auto* section = pe_binary_->get_section(section_name);

  if (!section) {
    return env.Null();
  }

  return PESection::NewInstance(env, section);
}

Napi::Value PEBinary::GetOptionalHeader(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();

  if (!pe_binary_) {
    return env.Null();
  }

  return OptionalHeader::NewInstance(env, &pe_binary_->optional_header());
}

// All abstract method implementations are now in BinaryImpl and forwarded via inline methods in the header

} // namespace node_lief
