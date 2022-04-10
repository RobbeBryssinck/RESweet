#pragma once

#include <functional>

// TODO: Event::Type?
enum class EventType
{
  kNone = 0,
  kTest,
  kOpenFile,
  kCloseApp,
};

class Event
{
public:
  Event() = default;
  Event(const Event&) = default;
  Event& operator=(const Event&) = default;

  virtual ~Event() = default;
  virtual EventType GetType() const = 0;
};

class OpenFileEvent final : public Event
{
public:
  static constexpr EventType eventType = EventType::kOpenFile;

  OpenFileEvent() = default;
  OpenFileEvent(std::string&& aFilename)
    : filename(std::move(aFilename))
  {}

  virtual ~OpenFileEvent() = default;
  virtual EventType GetType() const
  {
    return eventType;
  }

  std::string filename{};
};

class TestEvent final : public Event
{
public:
  static constexpr EventType eventType = EventType::kTest;

  virtual ~TestEvent() = default;
  virtual EventType GetType() const
  {
    return eventType;
  }
};

class CloseAppEvent final : public Event
{
public:
  static constexpr EventType eventType = EventType::kCloseApp;

  virtual ~CloseAppEvent() = default;
  virtual EventType GetType() const
  {
    return eventType;
  }
};

class EventDispatcher final
{
public:
  using Execution = std::function<void(const Event&)>;

  void Subscribe(const EventType& aEventType, Execution&& aExecution);

  template <class T>
  void Dispatch(const T& aEvent) const
  {
    auto subscription = observers.find(aEvent.GetType());
    if (subscription == observers.end())
      return;

    for (auto&& executor : subscription->second)
      executor(aEvent);
  }

private:
  std::unordered_map<EventType, std::vector<Execution>> observers;
};
