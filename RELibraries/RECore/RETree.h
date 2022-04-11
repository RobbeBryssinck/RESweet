#pragma once

#include "REPair.h"

#include <cstdint>
#include <optional>

template <class T>
class RETree
{
public:
  //RETree() = default;

  // TODO: test ctor, delete
  RETree()
  {
    pHead = new Node;
    pHead->value.first = 5;
    pHead->value.second = 3.f;
  }

  const T* operator[](uint32_t aKey) const
  {
    Node* pCurrentHead = pHead;
    while (pCurrentHead)
    {
      if (pCurrentHead->value.first == aKey)
        return &pCurrentHead->value.second;

      pCurrentHead = pCurrentHead->pNext;
    }

    return nullptr;
  }

  const T* Find(uint32_t aKey) const
  {
    Node* pCurrentHead = pHead;
    while (pCurrentHead)
    {
      if (pCurrentHead->value.first == aKey)
        return &pCurrentHead->value.second;

      pCurrentHead = pCurrentHead->pNext;
    }

    return nullptr;
  }

  void Insert(uint32_t aKey, const T& aValue)
  {
  }

private:
  struct Node
  {
    REPair<uint32_t, T> value{};
    Node* pNext = nullptr;
  };

  Node* pHead = nullptr;
};
