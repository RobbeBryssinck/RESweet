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
      // TODO: this directory stuff is bad
      auto oldPath = std::filesystem::current_path();
      std::filesystem::current_path(oldPath.parent_path());

      pBinary = Parsing::ParseFile("Samples/test64.exe");

      std::filesystem::current_path(oldPath);
    }

    static std::shared_ptr<Binary> pBinary;
  };

  std::shared_ptr<Binary> BinaryTest::pBinary = nullptr;

  TEST(Binary, LoadPe64)
  {
    // TODO: this directory stuff is bad
    auto oldPath = std::filesystem::current_path();
    std::filesystem::current_path(oldPath.parent_path());
    std::shared_ptr<Binary> pBinary = Parsing::ParseFile("Samples/test64.exe");
    std::filesystem::current_path(oldPath);

    EXPECT_TRUE(pBinary);
  }

  TEST_F(BinaryTest, GetTextSection)
  {
    const Section* pText = pBinary->GetTextSection();

    EXPECT_TRUE(pText);
  }
}
