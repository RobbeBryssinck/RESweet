#include <gtest/gtest.h>
#include <REList.h>

namespace
{
  class REListTest : public ::testing::Test
  {
  public:
    virtual ~REListTest() = default;
    virtual void SetUp()
    {
      list.Insert(4);
      list.Insert(6);
      list.Insert(3);
      list.Insert(9);
      list.Insert(11);
    }

    virtual void TearDown()
    {
    }

    REList<int> list{};
  };

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

  TEST_F(REListTest, GetSize5)
  {
    EXPECT_EQ(list.GetSize(), 5);
  }

  TEST_F(REListTest, Remove)
  {
    list.Remove(9);

    EXPECT_EQ(list.GetSize(), 4);
  }

  TEST_F(REListTest, Clear)
  {
    list.Clear();

    EXPECT_EQ(list.GetSize(), 0);
  }

  TEST_F(REListTest, RangeIterator)
  {
    int count = 0;

    for (auto& i : list)
      count++;

    EXPECT_EQ(count, list.GetSize());
  }

  TEST_F(REListTest, GetLast)
  {
    int& last = list.GetLast();

    EXPECT_EQ(last, 11);
  }
}