#include <gtest/gtest.h>
#include <RETree.h>

namespace
{
  TEST(RETree, Insert)
  {
    RETree<int> tree{};

    tree.Insert(4, 6);

    EXPECT_EQ(*tree[4], 6);
  }

  TEST(RETree, InsertMultiple)
  {
    RETree<int> tree{};

    tree.Insert(4, 6);
    tree.Insert(2, 9);
    tree.Insert(5, 10);
    tree.Insert(9, 6);

    EXPECT_EQ(*tree[4], 6);
    EXPECT_EQ(*tree[2], 9);
    EXPECT_EQ(*tree[5], 10);
    EXPECT_EQ(*tree[9], 6);
  }
}
