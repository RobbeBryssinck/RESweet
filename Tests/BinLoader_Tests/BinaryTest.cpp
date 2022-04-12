#include <gtest/gtest.h>
#include <BinLoader/Binary.h>
#include <BinLoader/BaseParser.h>
#include <filesystem>

namespace
{
  class BinaryTest : public ::testing::Test
  {
  public:
    static void SetUpTestSuite()
    {
      pBinary = Parsing::ParseFile("../Samples/test64.exe");
    }

    static std::shared_ptr<Binary> pBinary;
  };

  std::shared_ptr<Binary> BinaryTest::pBinary = nullptr;

  TEST(Binary, LoadPe64)
  {
    auto pBinary = Parsing::ParseFile("../Samples/test64.exe");

    EXPECT_TRUE(pBinary);
  }

  TEST(Binary, LoadPe32)
  {
    auto pBinary = Parsing::ParseFile("../Samples/test.exe");

    EXPECT_TRUE(pBinary);
  }

  TEST(Binary, LoadPeDotNet64)
  {
    auto pBinary = Parsing::ParseFile("../Samples/dotnet64test.exe");

    EXPECT_TRUE(pBinary);
  }

  TEST(Binary, LoadElf64)
  {
    auto pBinary = Parsing::ParseFile("../Samples/elf64");

    EXPECT_TRUE(pBinary);
  }

  TEST_F(BinaryTest, GetTextSection)
  {
    const Section* pText = pBinary->GetTextSection();

    EXPECT_TRUE(pText);
  }
}
