#include "Event.h"

void EventDispatcher::Subscribe(const Event::Type& aEventType, Execution&& aExecution)
{
  std::scoped_lock _(dispatcherMtx);
  observers[aEventType].push_back(aExecution);
}
