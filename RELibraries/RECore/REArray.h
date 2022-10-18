#pragma once

template <class T>
class REArray
{
public:

private:
  T* pData;

public:
  size_t size;
  size_t capacity;

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

  int Partition(int aLow, int aHigh)
  {
    const T& pivot = pData[aLow];
    int i = aLow;
    int j = aHigh;

    while (i < j)
    {
      do
      {
        i++;
      } while (pData[i] <= pivot);

      do
      {
        j--;
      } while (pData[j] > pivot);

      if (i < j)
        std::swap(pData[i], pData[j]);
    }

    std::swap(pData[aLow], pData[j]);

    return j;
  }

  void QuickSort()
  {
    QuickSort(0, size);
  }

  void QuickSort(int aLowest, int aHighest)
  {
    if (!std::is_trivial<T>())
      return;

    if (aLowest < aHighest)
    {
      int j = Partition(aLowest, aHighest);
      QuickSort(aLowest, j);
      QuickSort(j + 1, aHighest);
    }
  }
};
