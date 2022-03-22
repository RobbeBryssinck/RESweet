#pragma once

#include <string>
#include <memory>

// TODO: this class should really be in it's own thing, maybe a Core component?
class Reader
{
public:

  Reader(const std::string& acFile);
  Reader(Reader&& aReader) noexcept;

  template <class T>
  bool Read(T& apDestination, bool aPeak = false)
  {
    return ReadImpl(&apDestination, sizeof(T), aPeak);
  }
  bool ReadImpl(void* apDestination, const size_t acLength, bool aPeak = false);
  std::string ReadString();

  uint8_t* GetDataAtPosition();

  void Reset() { position = 0; }
  void Advance(const size_t acCount) { position += acCount; }

  size_t size = 0;
  size_t position = 0;
  std::unique_ptr<uint8_t[]> pBuffer{};
};
