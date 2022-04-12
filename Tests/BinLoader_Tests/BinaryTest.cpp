#include <gtest/gtest.h>
#include <BinLoader/Binary.h>
#include <BinLoader/BaseParser.h>
#include <filesystem>

namespace
{
  std::shared_ptr<Binary> ParseFile(const std::string& aFilename)
  {
    // TODO: this directory stuff is bad
    auto oldPath = std::filesystem::current_path();
    std::filesystem::current_path(oldPath.parent_path());

    auto pBinary = Parsing::ParseFile("Samples/" + aFilename);

    std::filesystem::current_path(oldPath);

    return pBinary;
  }

  class BinaryTest : public ::testing::Test
  {
  public:
    static void SetUpTestSuite()
    {
      pBinary = ParseFile("test64.exe");
    }

    static std::shared_ptr<Binary> pBinary;
  };

  std::shared_ptr<Binary> BinaryTest::pBinary = nullptr;

  TEST(Binary, LoadPe64)
  {
    auto pBinary = ParseFile("test64.exe");

    EXPECT_TRUE(pBinary);
  }

  TEST(Binary, LoadPe32)
  {
    auto pBinary = ParseFile("test.exe");

    EXPECT_TRUE(pBinary);
  }

  TEST(Binary, LoadPeDotNet64)
  {
    auto pBinary = ParseFile("dotnet64test.exe");

    EXPECT_TRUE(pBinary);
  }

  TEST(Binary, LoadElf64)
  {
    auto pBinary = ParseFile("elf64");

    EXPECT_TRUE(pBinary);
  }

  TEST_F(BinaryTest, GetTextSection)
  {
    const Section* pText = pBinary->GetTextSection();

    EXPECT_TRUE(pText);
  }
}
