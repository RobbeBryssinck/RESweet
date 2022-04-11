#pragma once

template <class First, class Second>
class REPair
{
public:
  REPair() = default;

  REPair(First aFirst, Second aSecond)
    : first(aFirst), second(aSecond)
  {}

  First first;
  Second second;
};

