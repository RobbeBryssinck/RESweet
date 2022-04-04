#pragma once

#include <string>
#include <memory>

class Reader
{
public:

  Reader() = default;
  Reader(Reader&& aReader) noexcept;

  bool LoadFromFile(const std::string& acFile);

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
