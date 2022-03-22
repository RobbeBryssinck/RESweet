#include "BaseParser.h"

#include <filesystem>
#include <fstream>
#include <spdlog/spdlog.h>

BaseParser::BaseParser(const std::string& acFile)
{
  size = std::filesystem::file_size(acFile);

  std::ifstream file(acFile, std::ios::binary);
  if (file.fail())
  {
    spdlog::error("Failed to read file contents.");
    return;
  }

  pBuffer = new uint8_t[size];

  file.read(reinterpret_cast<char*>(pBuffer), size);
}

BaseParser::~BaseParser()
{
  delete[] pBuffer;
}

bool BaseParser::ReadImpl(void* apDestination, const size_t acLength, bool aPeak)
{
  if (acLength + position > size)
    return false;

  std::memcpy(apDestination, pBuffer + position, acLength);
  if (!aPeak)
    position += acLength;

  return true;
}