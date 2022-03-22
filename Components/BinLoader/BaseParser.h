#pragma once

#include "loader.h"
#include <memory>

class BaseParser
{
public:

  BaseParser(const std::string& acFile);

protected:

  template <class T>
  bool Read(T* apDestination, bool aPeak = false)
  {
    return ReadImpl(apDestination, sizeof(T), aPeak);
  }

  bool ReadImpl(void* apDestination, const size_t acLength, bool aPeak = false);

  virtual Binary Parse() = 0;

  size_t size = 0;
  size_t position = 0;
  std::unique_ptr<uint8_t[]> pBuffer{};
};
