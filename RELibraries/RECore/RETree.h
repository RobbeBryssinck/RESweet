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
    pHead->pLeft = nullptr;
    pHead->pRight = nullptr;
  }

  const T* operator[](uint32_t aKey) const
  {
    Node* pCurrentHead = pHead;
    while (pCurrentHead)
    {
      if (pCurrentHead->value.first == aKey)
        return &pCurrentHead->value.second;

      if (aKey > pCurrentHead->value.first)
        pCurrentHead = pCurrentHead->pRight;
      else if (aKey < pCurrentHead->value.first)
        pCurrentHead = pCurrentHead->pLeft;
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

      pCurrentHead = pCurrentHead->pRight;
    }

    return nullptr;
  }

  void Insert(uint32_t aKey, const T& aValue)
  {
    if (!pHead)
    {
      pHead = new Node;
      pHead->value.first = aKey;
      pHead->value.second = aValue;
      pHead->pLeft = nullptr;
      pHead->pRight = nullptr;

      return;
    }
  }

private:
  struct Node
  {
    REPair<uint32_t, T> value{};
    Node* pLeft = nullptr;
    Node* pRight = nullptr;
  };

  Node* pHead = nullptr;
};
