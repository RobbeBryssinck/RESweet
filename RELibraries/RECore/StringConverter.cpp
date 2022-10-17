#include "StringConverter.h"

#include <locale>
#include <codecvt>

namespace StringConverter
{
  std::string FromWide(const std::wstring& aFrom)
  {
    std::wstring_convert<std::codecvt_utf8<wchar_t>, wchar_t> converter;
    return converter.to_bytes(aFrom);
  }

  std::wstring ToWide(const std::string& aFrom)
  {
    std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
    return converter.from_bytes(aFrom);
  }
}
