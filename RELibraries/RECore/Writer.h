#pragma once

#include "Buffer.h"

#include <cstdint>
#include <memory>
#include <string>

class Writer final : public Buffer
{
public:
  Writer();

  bool WriteToFile(const std::string& acFilename);

  template <class T>
  bool Write(T& apSource)
  {
    return WriteImpl(&apSource, sizeof(T));
  }
  bool WriteImpl(void* apSource, const size_t acLength);
};
