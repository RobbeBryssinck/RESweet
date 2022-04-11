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

  TEST(REList, InsertMultiple)
  {
    REList<int> list{};

    list.Insert(4);
    list.Insert(6);
    list.Insert(3);
    list.Insert(9);
    list.Insert(11);

    EXPECT_EQ(list.GetSize(), 5);
  }

  TEST(REList, GetSize0)
  {
    REList<int> list{};

    EXPECT_EQ(list.GetSize(), 0);
  }

  TEST(REList, GetSize5)
  {
    REList<int> list{};
    list.Insert(4);
    list.Insert(6);
    list.Insert(3);
    list.Insert(9);
    list.Insert(11);

    EXPECT_EQ(list.GetSize(), 5);
  }

  TEST(REList, Remove)
  {
    REList<int> list{};
    list.Insert(4);
    list.Insert(6);
    list.Insert(3);
    list.Insert(9);
    list.Insert(11);

    list.Remove(9);

    EXPECT_EQ(list.GetSize(), 4);
  }

  TEST(REList, Clear)
  {
    REList<int> list{};
    list.Insert(4);
    list.Insert(6);
    list.Insert(3);
    list.Insert(9);
    list.Insert(11);

    list.Clear();

    EXPECT_EQ(list.GetSize(), 0);
  }
}