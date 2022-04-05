#pragma once

#include <cstdint>
#include <memory>
#include <string>

class Writer
{
public:

  Writer();
  Writer(Writer&& aWriter) noexcept;

  bool WriteToFile(const std::string& acFilename);

  template <class T>
  bool Write(T& apSource)
  {
    return WriteImpl(&apSource, sizeof(T));
  }
  bool WriteImpl(void* apSource, const size_t acLength);

  uint8_t* GetDataAtPosition();

  void Resize(const size_t acNewSize);
  void Reset() { position = 0; }
  void Advance(const size_t acCount) { position += acCount; }

  size_t size = 0;
  size_t position = 0;
  std::unique_ptr<uint8_t[]> pBuffer{};
};
