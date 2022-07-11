#pragma once

template <class T>
class REArray
{
public:
  REArray()
  {
    capacity = 4;
    pData = new T[capacity];
    memset(pData, 0, sizeof(T) * 4);
    size = 0;
  }

  T& Add(const T& aNew)
  {
    if (size == capacity)
      Reallocate(2);

    pData[size] = aNew;

    size++;

    return pData[size-1];
  }

  T& operator[](size_t aIndex)
  {
    if (aIndex >= size)
      throw std::out_of_range("Index is larger than size.");

    return pData[aIndex];
  }

  const T& operator[](size_t aIndex) const
  {
    if (aIndex >= size)
      throw std::out_of_range("Index is larger than size.");

    return pData[aIndex];
  }

  void Reallocate(const int aMultiplier)
  {
    T* pOld = pData;
    capacity = capacity * aMultiplier;
    pData = new T[capacity];
    memmove(pData, pOld, sizeof(T) * capacity);
    delete[] pOld;
  }

private:
  T* pData;

public:
  size_t size;
  size_t capacity;
};
