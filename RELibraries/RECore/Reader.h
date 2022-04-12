#pragma once

#include <string>
#include <memory>
#include "Buffer.h"

class Reader final : public Buffer
{
public:
  Reader() = default;

  bool LoadFromFile(const std::string& acFilename);

  // This only works on simple types with no pointers
  template <class T>
  bool Read(T& apDestination, bool aPeak = false)
  {
    return ReadImpl(&apDestination, sizeof(T), aPeak);
  }
  bool ReadImpl(void* apDestination, const size_t acLength, bool aPeak = false);
  std::string ReadString();
  std::string ReadString(const size_t aLength);
};
