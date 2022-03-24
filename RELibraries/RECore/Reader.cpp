#include "Reader.h"

#include <filesystem>
#include <fstream>
#include <spdlog/spdlog.h>

Reader::Reader(Reader&& aReader) noexcept
{
  pBuffer = std::move(aReader.pBuffer);
  size = aReader.size;
}

bool Reader::LoadFromFile(const std::string& acFile)
{
  if (!std::filesystem::exists(acFile))
  {
    spdlog::error("File does not exist: {}", acFile);
    return false;
  }

  size = std::filesystem::file_size(acFile);

  std::ifstream file(acFile, std::ios::binary);
  if (file.fail())
  {
    spdlog::error("Failed to read file contents.");
    return false;
  }

  pBuffer = std::make_unique<uint8_t[]>(size);

  file.read(reinterpret_cast<char*>(pBuffer.get()), size);

  return true;
}

bool Reader::ReadImpl(void* apDestination, const size_t acLength, bool aPeak)
{
  if (acLength + position > size)
    return false;

  std::memcpy(apDestination, pBuffer.get() + position, acLength);

  if (!aPeak)
    position += acLength;

  return true;
}

std::string Reader::ReadString()
{
  std::string string = std::string(reinterpret_cast<const char*>(GetDataAtPosition()));
  Advance(string.size() + 1);
  return string;
}

// don't abuse this, cause unique_ptr and all
uint8_t* Reader::GetDataAtPosition()
{
  return pBuffer.get() + position;
}
