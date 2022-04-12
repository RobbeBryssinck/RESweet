#pragma once

#include <Reader.h>

#include <spdlog/spdlog.h>

#include <string>
#include <vector>
#include <ctype.h>

// TODO: move to cpp?
namespace Strings
{

constexpr bool IsValidCharacter(const char aCharacter)
{
  return (aCharacter > 0x1F && aCharacter < 0x7F) || aCharacter == '\r';
}

constexpr bool IsEndOfString(const char aCharacter)
{
  return aCharacter == '\00' || aCharacter == '\n';
}

std::vector<std::string> GetStringsFromData(Reader& aReader, const int acMinStringLength = 5)
{
  std::vector<std::string> strings{};

  char currentCharacter = '\00';
  constexpr size_t invalidPosition = std::numeric_limits<size_t>::max();
  size_t startPosition = invalidPosition;

  while (aReader.Read(currentCharacter))
  {
    if (IsValidCharacter(currentCharacter))
    {
      if (startPosition == invalidPosition)
        startPosition = aReader.position - 1;
    }
    else if (IsEndOfString(currentCharacter))
    {
      if (startPosition != invalidPosition
          && aReader.position - startPosition >= (acMinStringLength + 1)) // +1 to min string length to account for null byte
      {
        size_t stringSize = aReader.position - startPosition;

        aReader.position = startPosition;

        std::string str{};
        if (currentCharacter == '\00')
          str = aReader.ReadString();
        else
          str = aReader.ReadString(stringSize);

        strings.push_back(std::move(str));

        spdlog::debug("String at position {:X}: {}", startPosition, strings.back());
      }

      startPosition = invalidPosition;
    }
    else
      startPosition = invalidPosition;
  }

  // if string is at end of file
  if (startPosition != invalidPosition &&
      aReader.position - startPosition >= (acMinStringLength + 1)) // +1 to min string length to account for null byte
  {
    size_t stringSize = aReader.position - startPosition;
    aReader.position = startPosition;
    strings.push_back(std::move(aReader.ReadString(stringSize)));

    spdlog::debug("String at position {:X}: {}", startPosition, strings.back());
  }

  spdlog::debug("Strings count: {}", strings.size());

  return strings;
}

std::vector<std::string> GetStringsFromFile(const std::string& acFilename, const int acStringLength = 5)
{
  Reader reader{};
  if (!reader.LoadFromFile(acFilename))
  {
    spdlog::error("Failed to load to-parse file");
    return std::vector<std::string>{};
  }

  return GetStringsFromData(reader, acStringLength);
}

} // namespace Strings
