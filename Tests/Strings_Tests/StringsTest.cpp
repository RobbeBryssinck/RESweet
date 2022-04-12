#include <gtest/gtest.h>
#include <Strings.h>

using namespace Strings;

namespace
{
  TEST(StringsTests, LoadBinary)
  {
    std::vector<std::string> strs = GetStringsFromFile("../Samples/test64.exe");

    ASSERT_EQ(strs.size(), 131);
  }

  TEST(StringsTests, LoadTxt)
  {
    std::vector<std::string> strs = GetStringsFromFile("../Samples/test.txt");

    ASSERT_EQ(strs.size(), 4);
  }
}
