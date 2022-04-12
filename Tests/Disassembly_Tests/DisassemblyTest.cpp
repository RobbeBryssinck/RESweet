#include <gtest/gtest.h>

#include <Disassembly/Disassembly.h>
#include <BinLoader/BaseParser.h>

namespace
{
  class DisassemblyTest : public ::testing::Test
  {
  public:
    static void SetUpTestSuite()
    {
      pBinary = Parsing::ParseFile("../Samples/test64.exe");
    }

    static std::shared_ptr<Binary> pBinary;
  };

  std::shared_ptr<Binary> DisassemblyTest::pBinary = nullptr;

  TEST_F(DisassemblyTest, Linear)
  {
    auto functions = Disassembly::Disassemble(pBinary, false);

    EXPECT_EQ(functions.size(), 141);
  }

  TEST_F(DisassemblyTest, Recursive)
  {
    auto functions = Disassembly::Disassemble(pBinary);

    EXPECT_EQ(functions.size(), 113);
  }
}
