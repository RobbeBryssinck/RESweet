#include "Event.h"

void EventDispatcher::Subscribe(const EventType& aEventType, Execution&& aExecution)
{
  observers[aEventType].push_back(aExecution);
}
