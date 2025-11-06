/*
 * LIEF PE Section Binding with full read/write support
 */

#include "section.h"
#include <LIEF/logging.hpp>

namespace node_lief {

// Static storage for constructor
static Napi::FunctionReference* pe_section_constructor = nullptr;

Napi::Object PESection::Init(Napi::Env env, Napi::Object exports) {
  Napi::Function constructor = DefineClass(env, "Section", {
    InstanceAccessor<&PESection::GetName>("name"),
    InstanceAccessor<&PESection::GetType>("type"),
    InstanceAccessor<&PESection::GetVirtualAddress>("virtualAddress"),
    InstanceAccessor<&PESection::GetSize, &PESection::SetSize>("size"),
    InstanceAccessor<&PESection::GetFileOffset>("fileOffset"),
    InstanceAccessor<&PESection::GetVirtualSize, &PESection::SetVirtualSize>("virtualSize"),
    InstanceAccessor<&PESection::GetContent, &PESection::SetContent>("content"),
    InstanceAccessor<&PESection::GetOffset>("offset"),
    InstanceAccessor<&PESection::GetCharacteristics>("characteristics"),
  });

  pe_section_constructor = new Napi::FunctionReference();
  *pe_section_constructor = Napi::Persistent(constructor);

  // Return the constructor itself
  return constructor;
}

PESection::PESection(const Napi::CallbackInfo& info)
    : Napi::ObjectWrap<PESection>(info), section_(nullptr) {}

Napi::Object PESection::NewInstance(Napi::Env env, LIEF::PE::Section* section) {
  if (!pe_section_constructor) {
    Napi::Error::New(env, "PESection constructor not initialized").ThrowAsJavaScriptException();
    return Napi::Object::New(env);
  }
  Napi::Object obj = pe_section_constructor->New({});
  PESection* unwrapped = Napi::ObjectWrap<PESection>::Unwrap(obj);
  unwrapped->section_ = section;
  return obj;
}

Napi::Value PESection::GetName(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (!section_) return env.Null();
  return Napi::String::New(env, section_->name());
}

Napi::Value PESection::GetType(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (!section_) return env.Null();
  // PE sections don't have a simple type string in LIEF
  // Return a generic type string
  return Napi::String::New(env, "PE_SECTION");
}

Napi::Value PESection::GetVirtualAddress(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (!section_) return env.Null();
  return Napi::BigInt::New(env, section_->virtual_address());
}

Napi::Value PESection::GetSize(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (!section_) return env.Null();
  return Napi::BigInt::New(env, section_->size());
}

void PESection::SetSize(const Napi::CallbackInfo& info, const Napi::Value& value) {
  if (!section_ || !value.IsBigInt()) return;
  bool lossless = false;
  uint64_t new_size = value.As<Napi::BigInt>().Uint64Value(&lossless);
  section_->size(new_size);
}

Napi::Value PESection::GetFileOffset(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (!section_) return env.Null();
  return Napi::BigInt::New(env, section_->offset());
}

Napi::Value PESection::GetVirtualSize(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (!section_) return env.Null();
  // PE sections have a proper virtual_size() method
  return Napi::BigInt::New(env, static_cast<uint64_t>(section_->virtual_size()));
}

void PESection::SetVirtualSize(const Napi::CallbackInfo& info, const Napi::Value& value) {
  if (!section_ || !value.IsBigInt()) return;
  bool lossless = false;
  uint64_t new_size = value.As<Napi::BigInt>().Uint64Value(&lossless);
  // PE sections have a proper virtual_size() setter
  section_->virtual_size(new_size);
}

Napi::Value PESection::GetContent(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (!section_) return env.Null();

  auto content = section_->content();
  if (content.empty()) {
    return Napi::Buffer<uint8_t>::New(env, 0);
  }

  // Use Buffer::Copy to efficiently copy binary data
  // This is much more efficient than creating an array with millions of Number objects
  return Napi::Buffer<uint8_t>::Copy(env, content.data(), content.size());
}

void PESection::SetContent(const Napi::CallbackInfo& info, const Napi::Value& value) {
  if (!section_) return;

  std::vector<uint8_t> new_content;

  if (value.IsArray()) {
    auto arr = value.As<Napi::Array>();
    new_content.reserve(arr.Length());
    for (uint32_t i = 0; i < arr.Length(); i++) {
      auto val = arr.Get(i);
      if (val.IsNumber()) {
        new_content.push_back(static_cast<uint8_t>(val.As<Napi::Number>().Uint32Value()));
      }
    }
  } else if (value.IsBuffer()) {
    auto buffer = value.As<Napi::Buffer<uint8_t>>();
    new_content.assign(buffer.Data(), buffer.Data() + buffer.Length());
  }

  if (!new_content.empty()) {
    section_->content(new_content);
  }
}

Napi::Value PESection::GetOffset(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (!section_) return env.Null();
  return Napi::BigInt::New(env, section_->offset());
}

Napi::Value PESection::GetCharacteristics(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (!section_) return env.Null();
  return Napi::Number::New(env, section_->characteristics());
}

} // namespace node_lief
