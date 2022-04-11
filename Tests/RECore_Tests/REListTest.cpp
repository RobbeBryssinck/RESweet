#include <gtest/gtest.h>
#include <REList.h>

namespace
{
  TEST(REList, Insert)
  {
    REList<int> list{};

    list.Insert(4);

    EXPECT_EQ(*list.cbegin(), 4);
  }
}