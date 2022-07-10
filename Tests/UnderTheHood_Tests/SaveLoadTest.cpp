#include <gtest/gtest.h>
#include <SaveLoad/RESF.h>

namespace
{
  class LoadTest : public ::testing::Test
  {
  public:
    virtual ~LoadTest() = default;
    virtual void SetUp()
    {

    }
    virtual void TearDown()
    {

    }
  };

  TEST(SaveLoad, LoadFile)
  {
    RESF resf{};


  }
}
