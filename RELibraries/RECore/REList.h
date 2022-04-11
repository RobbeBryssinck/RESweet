#pragma once

#include <cstdint>

template <class T>
class REList
{
public:
  T& GetLast() const
  {
    Node* pCurrent = pHead;
    while (pCurrent)
      pCurrent = pCurrent->pNext;

    return pCurrent->value;
  }

  void Insert(const T& aValue)
  {
    if (!pHead)
    {
      pHead = new Node(aValue);
      return;
    }

    Node* pCurrent = pHead;
    while (pCurrent->pNext)
      pCurrent = pCurrent->pNext;

    pCurrent->pNext = new Node(aValue);
  }

  void Remove(const T& aValue)
  {
    if (!pHead)
      return;

    Node* pCurrent = pHead;
    Node* pPrevious = nullptr;
    while (pCurrent->value != aValue)
    {
      pPrevious = pCurrent;
      pCurrent = pCurrent->pNext;
    }

    if (pPrevious)
      pPrevious->pNext = pCurrent->pNext;

    delete pCurrent;
  }

  void Clear()
  {
    if (!pHead)
      return;

    Node* pCurrent = pHead;
    Node* pNext = nullptr;
    while (pCurrent)
    {
      pNext = pCurrent->pNext;
      delete pCurrent;
      pCurrent = pNext;
    }

    pHead = nullptr;
  }

  constexpr bool IsEmpty() const { return !pHead; }

  struct Node;

  struct Iterator
  {
    Iterator(Node* apNode)
      : pNode(apNode)
    {}

    Iterator operator++()
    {
      pNode = pNode->pNext;
      return *this;
    }

    bool operator!=(const Iterator& aRhs) const { return pNode != aRhs.pNode; }
    bool operator==(const Iterator& aRhs) const { return pNode == aRhs.pNode; }

    T& operator*() const { return pNode->value; }
    T* operator->() const { return &pNode->value; }

  private:
    Node* pNode{};
  };

  Iterator begin() { return Iterator(pHead); }
  Iterator end() { return Iterator(nullptr); }
  const Iterator cbegin() { return Iterator(pHead); }
  const Iterator cend() { return Iterator(nullptr); }

  struct Node
  {
    Node(T aValue)
      : value(aValue),
        pNext(nullptr)
    {}

    T value{};
    Node* pNext{};
  };

private:
  Node* pHead{};
};
