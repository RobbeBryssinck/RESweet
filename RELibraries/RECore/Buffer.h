#pragma once

#include <cstdint>
#include <memory>

class Buffer
{
public:
  Buffer() = default;
  Buffer(const Buffer& aBuffer) = default;
  Buffer(Buffer&& aBuffer) noexcept;
  Buffer& operator=(const Buffer& aBuffer) = default;
  Buffer& operator=(Buffer&& aBuffer) noexcept;

  uint8_t* GetDataAtPosition();

  bool IsOverflow(const size_t acLength) const;

  void Resize(const size_t acNewSize);
  void Reset() { position = 0; }
  void Advance(const size_t acCount) { position += acCount; }

  size_t size = 0;
  size_t position = 0;
  std::unique_ptr<uint8_t[]> pData{};
};
