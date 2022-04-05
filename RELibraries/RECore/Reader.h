#pragma once

#include <string>
#include <memory>
#include "Buffer.h"

class Reader final : public Buffer
{
public:
  Reader() = default;

  bool LoadFromFile(const std::string& acFile);

  template <class T>
  bool Read(T& apDestination, bool aPeak = false)
  {
    return ReadImpl(&apDestination, sizeof(T), aPeak);
  }
  bool ReadImpl(void* apDestination, const size_t acLength, bool aPeak = false);
  std::string ReadString();
};
