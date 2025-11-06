/*
 * LIEF Node.js Bindings - Module Initialization
 *
 * This file initializes the LIEF Node.js addon and exposes the main classes
 * and functions to the JavaScript side.
 */

#include <napi.h>
#include "abstract/binary.h"
#include "abstract/section.h"
#include "abstract/segment.h"
#include "abstract/symbol.h"
#include "elf/binary.h"
#include "pe/binary.h"
#include "pe/section.h"
#include "pe/optional_header.h"
#include "macho/binary.h"
#include "macho/fat_binary.h"
#include <LIEF/logging.hpp>

namespace node_lief {

// Forward declarations
extern Napi::Value Parse(const Napi::CallbackInfo& info);
extern Napi::Value MachOParse(const Napi::CallbackInfo& info);

void InitLogging(Napi::Env env, Napi::Object exports) {
  Napi::Object logging = Napi::Object::New(env);

  // logging.disable()
  logging.Set("disable", Napi::Function::New(env, [](const Napi::CallbackInfo& info) {
    LIEF::logging::disable();
    return info.Env().Undefined();
  }));

  // logging.enable()
  logging.Set("enable", Napi::Function::New(env, [](const Napi::CallbackInfo& info) {
    LIEF::logging::enable();
    return info.Env().Undefined();
  }));

  exports.Set("logging", logging);
}

Napi::Object Init(Napi::Env env, Napi::Object exports) {
  // Initialize Abstract API
  exports.Set("Abstract", Napi::Object::New(env));
  auto abstract = exports.Get("Abstract").As<Napi::Object>();

  // Abstract classes
  abstract.Set("Binary", AbstractBinary::Init(env, exports));
  abstract.Set("Section", Section::Init(env, exports));
  // abstract.Set("Segment", Segment::Init(env, exports));  // TODO: LIEF doesn't have an abstract Segment class
  abstract.Set("Symbol", AbstractSymbol::Init(env, exports));

  // Format-specific APIs
  exports.Set("ELF", Napi::Object::New(env));
  auto elf = exports.Get("ELF").As<Napi::Object>();
  elf.Set("Binary", ELFBinary::Init(env, exports));

  exports.Set("PE", Napi::Object::New(env));
  auto pe = exports.Get("PE").As<Napi::Object>();
  pe.Set("Binary", PEBinary::Init(env, exports));
  pe.Set("Section", PESection::Init(env, exports));
  pe.Set("OptionalHeader", OptionalHeader::Init(env, exports));

  exports.Set("MachO", Napi::Object::New(env));
  auto macho = exports.Get("MachO").As<Napi::Object>();
  macho.Set("Binary", MachOBinary::Init(env, exports));
  macho.Set("FatBinary", MachOFatBinary::Init(env, exports));
  macho.Set("Segment", Segment::Init(env, exports));
  macho.Set("parse", Napi::Function::New(env, MachOParse));

  // Top-level parsing functions
  exports.Set("parse", Napi::Function::New(env, Parse));

  // Logging API
  InitLogging(env, exports);

  return exports;
}

NODE_API_MODULE(node_lief, Init)

} // namespace node_lief
