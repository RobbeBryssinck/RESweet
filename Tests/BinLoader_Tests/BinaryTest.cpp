#include <gtest/gtest.h>
#include <BinLoader/Binary.h>
#include <BinLoader/BaseParser.h>

namespace
{
  TEST(Binary, LoadPe64)
  {
    std::shared_ptr<Binary> pBinary = Parsing::ParseFile("../Samples/test64.exe");

    EXPECT_NE(pBinary, nullptr);
  }
}
