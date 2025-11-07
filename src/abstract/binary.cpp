/*
 * LIEF Abstract Binary Binding
 *
 * Exposes the generic Binary class which works across all formats (ELF, PE, MachO)
 */

#include "binary.h"
#include "section.h"
#include "../elf/binary.h"
#include "../macho/binary.h"
#include "../pe/binary.h"
#include <LIEF/LIEF.hpp>
#include <sstream>

namespace node_lief {

// Static storage for constructor (not using instance data to avoid conflicts)
static Napi::FunctionReference* binary_constructor = nullptr;

Napi::Object AbstractBinary::Init(Napi::Env env, Napi::Object exports) {
  Napi::Function constructor = DefineClass(env, "Binary", {
    // Properties
    InstanceAccessor<&AbstractBinary::GetFormat>("format"),
    InstanceAccessor<&AbstractBinary::GetEntrypoint>("entrypoint"),
    InstanceAccessor<&AbstractBinary::GetIsPie>("isPie"),
    InstanceAccessor<&AbstractBinary::GetHasNx>("hasNx"),
    InstanceAccessor<&AbstractBinary::GetHeader>("header"),

    // Methods
    InstanceMethod<&AbstractBinary::GetSegments>("segments"),
    InstanceMethod<&AbstractBinary::GetSections>("sections"),
    InstanceMethod<&AbstractBinary::GetSymbols>("symbols"),
    InstanceMethod<&AbstractBinary::GetRelocations>("relocations"),
    InstanceMethod<&AbstractBinary::GetSymbol>("getSymbol"),
    InstanceMethod<&AbstractBinary::PatchAddress>("patchAddress"),
    InstanceMethod<&AbstractBinary::Write>("write"),
  });

  // Store constructor in static variable
  binary_constructor = new Napi::FunctionReference();
  *binary_constructor = Napi::Persistent(constructor);

  exports.Set("Binary", constructor);
  return exports;
}

// Helper to create Binary instances from parsed LIEF binaries
Napi::Object AbstractBinary::NewInstance(Napi::Env env, std::unique_ptr<LIEF::Binary> binary) {
  if (!binary_constructor) {
    Napi::Error::New(env, "Binary constructor not initialized").ThrowAsJavaScriptException();
    return Napi::Object::New(env);
  }

  // Create an empty Binary object (constructor will be called but won't parse)
  Napi::Object obj = binary_constructor->New({});

  // Get the C++ wrapper and replace its binary
  AbstractBinary* wrapper = Napi::ObjectWrap<AbstractBinary>::Unwrap(obj);
  wrapper->owned_binary_ = std::move(binary);
  wrapper->binary_ = wrapper->owned_binary_.get();

  return obj;
}

AbstractBinary::AbstractBinary(const Napi::CallbackInfo& info)
    : Napi::ObjectWrap<AbstractBinary>(info), BinaryImpl() {
  Napi::Env env = info.Env();

  // Allow construction with no args (for NewInstance helper)
  if (info.Length() == 0) {
    return;
  }

  if (info.Length() < 1) {
    Napi::TypeError::New(env, "Binary constructor requires a file path").ThrowAsJavaScriptException();
    return;
  }

  if (!info[0].IsString()) {
    Napi::TypeError::New(env, "Binary constructor requires a string file path").ThrowAsJavaScriptException();
    return;
  }

  std::string filename = info[0].As<Napi::String>();

  // Parse the binary file
  auto parsed = LIEF::Parser::parse(filename);
  if (!parsed) {
    Napi::Error::New(env, "Failed to parse binary file").ThrowAsJavaScriptException();
    return;
  }

  owned_binary_ = std::move(parsed);
  binary_ = owned_binary_.get();
}

// All method implementations are now in BinaryImpl and forwarded via inline methods in the header

Napi::Value Parse(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();

  if (info.Length() < 1 || !info[0].IsString()) {
    Napi::TypeError::New(env, "parse() requires a file path string")
        .ThrowAsJavaScriptException();
    return env.Null();
  }

  std::string filename = info[0].As<Napi::String>();

  // Parse the binary file
  auto parsed = LIEF::Parser::parse(filename);
  if (!parsed) {
    Napi::Error::New(env, "Failed to parse binary file").ThrowAsJavaScriptException();
    return env.Null();
  }

  // Return the concrete type based on format (matching Python LIEF API)
  auto format = parsed->format();

  if (format == LIEF::Binary::FORMATS::MACHO) {
    // For MachO, parse with format-specific parser to get proper Binary
    auto fat_binary = LIEF::MachO::Parser::parse(filename);
    if (!fat_binary || fat_binary->size() == 0) {
      Napi::Error::New(env, "Failed to parse MachO binary").ThrowAsJavaScriptException();
      return env.Null();
    }
    // Take the first binary from the FatBinary
    auto macho_binary = fat_binary->take(0);
    if (!macho_binary) {
      Napi::Error::New(env, "Failed to extract MachO binary").ThrowAsJavaScriptException();
      return env.Null();
    }
    return MachOBinary::NewInstance(env, std::move(macho_binary));
  }

  if (format == LIEF::Binary::FORMATS::PE) {
    // For PE, parse with format-specific parser to get proper Binary
    auto pe_binary = LIEF::PE::Parser::parse(filename);
    if (!pe_binary) {
      Napi::Error::New(env, "Failed to parse PE binary").ThrowAsJavaScriptException();
      return env.Null();
    }
    return PEBinary::NewInstance(env, std::move(pe_binary));
  }

  if (format == LIEF::Binary::FORMATS::ELF) {
    // For ELF, parse with format-specific parser to get proper Binary
    auto elf_binary = LIEF::ELF::Parser::parse(filename);
    if (!elf_binary) {
      Napi::Error::New(env, "Failed to parse ELF binary").ThrowAsJavaScriptException();
      return env.Null();
    }
    return ELFBinary::NewInstance(env, std::move(elf_binary));
  }

  // For other formats, return the abstract wrapper
  return AbstractBinary::NewInstance(env, std::move(parsed));
}

} // namespace node_lief
