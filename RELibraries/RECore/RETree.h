#pragma once

#include "REPair.h"

#include <cstdint>

template <class T>
class RETree
{
public:
  T& Find(uint32_t aKey);
  void Insert(uint32_t aKey, const T& aValue);

private:
  struct Node
  {
    REPair<uint32_t, T>* pValue{};
    Node* pNext{};
  };

  Node* pHead{};
};
