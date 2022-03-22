#pragma once

#include "loader.h"

class BaseParser
{
public:

  BaseParser(const std::string& acFile);
  ~BaseParser();

protected:

  template <class T>
  bool Read(T* apDestination)
  {
    const size_t cLength = sizeof(T);

    if (cLength + position > size)
      return false;

    std::memcpy(apDestination, pBuffer + position, cLength);
    position += cLength;

    return true;
  }

  virtual Binary Parse() = 0;

  size_t size = 0;
  size_t position = 0;
  uint8_t* pBuffer = nullptr;
};
