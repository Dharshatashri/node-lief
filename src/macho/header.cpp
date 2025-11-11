/*
 * LIEF MachO Header Binding
 */

#include "header.h"
#include <LIEF/logging.hpp>

namespace node_lief {

// Static storage for constructor
static Napi::FunctionReference* macho_header_constructor = nullptr;

Napi::Object MachOHeader::Init(Napi::Env env, Napi::Object exports) {
  Napi::Function constructor = DefineClass(env, "Header", {
    // MachO-specific properties matching LIEF API
    InstanceAccessor<&MachOHeader::GetCpuType>("cpuType"),
    InstanceAccessor<&MachOHeader::GetCpuSubtype>("cpuSubtype"),
    InstanceAccessor<&MachOHeader::GetFileType>("fileType"),
    InstanceAccessor<&MachOHeader::GetFlags>("flags"),
    InstanceAccessor<&MachOHeader::GetMagic>("magic"),
    InstanceAccessor<&MachOHeader::GetNbCmds>("nbCmds"),
    InstanceAccessor<&MachOHeader::GetSizeofCmds>("sizeofCmds"),
    InstanceAccessor<&MachOHeader::GetIs32Bit>("is32Bit"),
    InstanceAccessor<&MachOHeader::GetIs64Bit>("is64Bit"),
  });

  macho_header_constructor = new Napi::FunctionReference();
  *macho_header_constructor = Napi::Persistent(constructor);

  // Return the constructor itself
  return constructor;
}

MachOHeader::MachOHeader(const Napi::CallbackInfo& info)
    : Napi::ObjectWrap<MachOHeader>(info), header_(nullptr) {}

Napi::Object MachOHeader::NewInstance(Napi::Env env, const LIEF::MachO::Header* header) {
  if (!macho_header_constructor) {
    Napi::Error::New(env, "MachOHeader constructor not initialized").ThrowAsJavaScriptException();
    return Napi::Object::New(env);
  }
  Napi::Object obj = macho_header_constructor->New({});
  MachOHeader* unwrapped = Napi::ObjectWrap<MachOHeader>::Unwrap(obj);
  unwrapped->header_ = header;
  return obj;
}

Napi::Value MachOHeader::GetCpuType(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (!header_) return env.Null();
  // Return as signed 32-bit integer (CPU_TYPE is int32_t)
  return Napi::Number::New(env, static_cast<int32_t>(header_->cpu_type()));
}

Napi::Value MachOHeader::GetCpuSubtype(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (!header_) return env.Null();
  return Napi::Number::New(env, header_->cpu_subtype());
}

Napi::Value MachOHeader::GetFileType(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (!header_) return env.Null();
  return Napi::Number::New(env, static_cast<uint32_t>(header_->file_type()));
}

Napi::Value MachOHeader::GetFlags(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (!header_) return env.Null();
  return Napi::Number::New(env, header_->flags());
}

Napi::Value MachOHeader::GetMagic(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (!header_) return env.Null();
  return Napi::Number::New(env, static_cast<uint32_t>(header_->magic()));
}

Napi::Value MachOHeader::GetNbCmds(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (!header_) return env.Null();
  return Napi::Number::New(env, header_->nb_cmds());
}

Napi::Value MachOHeader::GetSizeofCmds(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (!header_) return env.Null();
  return Napi::Number::New(env, header_->sizeof_cmds());
}

Napi::Value MachOHeader::GetIs32Bit(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (!header_) return env.Null();
  return Napi::Boolean::New(env, header_->is_32bit());
}

Napi::Value MachOHeader::GetIs64Bit(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (!header_) return env.Null();
  return Napi::Boolean::New(env, header_->is_64bit());
}

} // namespace node_lief
