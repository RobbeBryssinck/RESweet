#include "Event.h"

void EventDispatcher::Subscribe(const Event::Type& aEventType, Execution&& aExecution)
{
  observers[aEventType].push_back(aExecution);
}
