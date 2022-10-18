#include <gtest/gtest.h>
#include <REArray.h>

#include <iostream>

namespace
{
  class REArrayTest : public ::testing::Test
  {
  public:
    virtual ~REArrayTest() = default;
    virtual void SetUp()
    {
    }

    virtual void TearDown()
    {
    }

    REArray<int> list{};
  };

  TEST(REArray, Insert)
  {
    REArray<int> arr{};
    arr.Add(5);
    arr.Add(3);
    arr.Add(20);
    arr.Add(1);
    arr.Add(4);

    arr.QuickSort();

    std::cout << arr.size << std::endl;

    /*
    std::vector<int> a{ 5 };
    a.push_back(3);
    
    REArray<int> list{};

    list.Insert(4);

    EXPECT_EQ(*list.cbegin(), 4);
    */
  }
}
