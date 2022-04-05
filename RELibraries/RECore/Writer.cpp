#include "Writer.h"

Writer::Writer()
{
  constexpr size_t initialSize = 1024;
  pData = std::make_unique<uint8_t[]>(8);
  size = 8;
}

bool Writer::WriteToFile(const std::string& acFilename)
{
  // TODO
  return true;
}

bool Writer::WriteImpl(void* apSource, const size_t acLength)
{
  if (IsOverflow(acLength))
  {
    size_t newLength = size + acLength;
    if (acLength < 1024)
      newLength = size + 1024;

    Resize(newLength);
  }

  std::memcpy(GetDataAtPosition(), apSource, acLength);

  Advance(acLength);

  return true;
}