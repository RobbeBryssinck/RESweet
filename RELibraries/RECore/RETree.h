#pragma once

#include "REPair.h"

#include <cstdint>
#include <optional>

template <class T>
class RETree
{
public:
  RETree() = default;

  const T* operator[](uint32_t aKey) const
  {
    if (!pHead)
      return nullptr;

    Node* pEntry = pHead->FindEntry(aKey);
    if (!pEntry)
      return nullptr;

    return &pEntry->value.second;
  }

  void Insert(const uint32_t aKey, const T& aValue)
  {
    if (!pHead)
    {
      pHead = new Node();
      pHead->value = REPair<uint32_t, T>(aKey, aValue);
      return;
    }

    Node* pEntry = pHead->FindPlacement(aKey);
    if (!pEntry)
      return;

    Node* pNewNode = new Node();
    pNewNode->value = REPair<uint32_t, T>(aKey, aValue);

    if (aKey > pEntry->value.first)
      pEntry->pRight = pNewNode;
    else if (aKey < pEntry->value.first)
      pEntry->pLeft = pNewNode;
  }

private:
  struct Node
  {
    Node* FindEntry(const uint32_t aKey)
    {
      if (aKey > value.first)
      {
        if (pRight)
          return pRight->FindEntry(aKey);

        return nullptr;
      }
      else if (aKey < value.first)
      {
        if (pLeft)
          return pLeft->FindEntry(aKey);

        return nullptr;
      }

      return this;
    }

    Node* FindPlacement(const uint32_t aKey)
    {
      if (aKey > value.first)
      {
        if (pRight)
          return pRight->FindPlacement(aKey);

        return this;
      }
      else if (aKey < value.first)
      {
        if (pLeft)
          return pLeft->FindPlacement(aKey);

        return this;
      }

      return nullptr;
    }

    REPair<uint32_t, T> value{};
    Node* pLeft = nullptr;
    Node* pRight = nullptr;
  };

  Node* pHead = nullptr;
};
