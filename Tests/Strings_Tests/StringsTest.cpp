#include <gtest/gtest.h>
#include <Strings.h>

namespace
{
  TEST(Strings, LoadBinary)
  {
    std::vector<std::string> strings = Strings::GetStringsFromFile("../Samples/test64.exe");
  }

  TEST(Strings, LoadTxt)
  {
  }
}
