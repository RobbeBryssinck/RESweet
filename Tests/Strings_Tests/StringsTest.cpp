#include <gtest/gtest.h>
#include <Strings.h>

namespace
{
  TEST(StringsTests, LoadBinary)
  {
    std::vector<std::string> strs = Strings::GetStringsFromFile("../Samples/test64.exe");

    ASSERT_EQ(strs.size(), 131);
  }

  TEST(StringsTests, LoadTxt)
  {
    std::vector<std::string> strs = Strings::GetStringsFromFile("../Samples/test.txt");

    EXPECT_EQ(strs.size(), 4);
    ASSERT_EQ(strs[0], "hello");
    ASSERT_EQ(strs[1], "monday");
    ASSERT_EQ(strs[2], "how are you?");
    ASSERT_EQ(strs[3], "testing");
  }

  TEST(StringsTests, LoadTxtSize4)
  {
    std::vector<std::string> strs = Strings::GetStringsFromFile("../Samples/test.txt", 3);

    EXPECT_EQ(strs.size(), 5);
    ASSERT_EQ(strs[0], "hello");
    ASSERT_EQ(strs[1], "monday");
    ASSERT_EQ(strs[2], "how are you?");
    ASSERT_EQ(strs[3], "cop");
    ASSERT_EQ(strs[4], "testing");
  }
}
