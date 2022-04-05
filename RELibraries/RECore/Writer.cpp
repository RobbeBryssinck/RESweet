#include "Writer.h"

Writer::Writer()
{
  // TODO: what to alloc to start?
  pBuffer = std::make_unique<uint8_t[]>(8);
  size = 8;
}

bool Writer::WriteImpl(void* apSource, const size_t acLength)
{
  if (position + acLength > size)
    Resize(size + acLength);

  std::memcpy(GetDataAtPosition(), apSource, acLength);

  Advance(acLength);

  return true;
}

void Writer::Resize(const size_t acNewSize)
{
  std::unique_ptr<uint8_t[]> pNewBuffer = std::make_unique<uint8_t[]>(acNewSize);

  std::memcpy(pNewBuffer.get(), pBuffer.get(), size);
  pBuffer = std::move(pNewBuffer);
  size = acNewSize;
}

// don't abuse this, cause unique_ptr and all
uint8_t* Writer::GetDataAtPosition()
{
  return pBuffer.get() + position;
}