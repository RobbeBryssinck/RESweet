#include "Reader.h"

#include <filesystem>
#include <fstream>
#include <spdlog/spdlog.h>

bool Reader::LoadFromFile(const std::string& acFilename)
{
  if (!std::filesystem::exists(acFilename))
  {
    spdlog::error("File does not exist: {}", acFilename);
    return false;
  }

  size = std::filesystem::file_size(acFilename);

  std::ifstream file(acFilename, std::ios::binary);
  if (file.fail())
  {
    spdlog::error("Failed to read file contents of file {}", acFilename);
    return false;
  }

  pData = std::make_unique<uint8_t[]>(size);

  file.read(reinterpret_cast<char*>(pData.get()), size);

  return true;
}

bool Reader::ReadImpl(void* apDestination, const size_t acLength, bool aPeak)
{
  if (IsOverflow(acLength))
    return false;

  std::memcpy(apDestination, GetDataAtPosition(), acLength);

  if (!aPeak)
    Advance(acLength);

  return true;
}

std::string Reader::ReadString()
{
  std::string string = std::string(reinterpret_cast<const char*>(GetDataAtPosition()));
  Advance(string.size() + 1);
  return string;
}
