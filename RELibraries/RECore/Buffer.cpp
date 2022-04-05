#include "Buffer.h"

Buffer::Buffer(Buffer&& aBuffer) noexcept
{
  pData = std::move(aBuffer.pData);
  size = aBuffer.size;
}

// don't abuse this, cause unique_ptr and all
uint8_t* Buffer::GetDataAtPosition()
{
  return pData.get() + position;
}

bool Buffer::IsOverflow(const size_t acLength) const
{
  return position + acLength > size;
}

void Buffer::Resize(const size_t acNewSize)
{
  std::unique_ptr<uint8_t[]> pNewData = std::make_unique<uint8_t[]>(acNewSize);

  std::memcpy(pNewData.get(), pData.get(), size);
  pData = std::move(pNewData);
  size = acNewSize;
}
