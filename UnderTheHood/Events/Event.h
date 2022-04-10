#pragma once

#include <functional>

class Event
{
public:
  enum class Type
  {
    kNone = 0,
    kTest,
    kOpenFile,
    kSave,
    kLoad,
    kClose,
  };

  Event() = default;
  Event(const Event&) = default;
  Event& operator=(const Event&) = default;

  virtual ~Event() = default;
  virtual Type GetType() const = 0;
};

class OpenFileEvent final : public Event
{
public:
  static constexpr Type eventType = Type::kOpenFile;

  OpenFileEvent() = default;
  OpenFileEvent(std::string&& aFilename)
    : filename(std::move(aFilename))
  {}

  virtual ~OpenFileEvent() = default;
  virtual Type GetType() const
  {
    return eventType;
  }

  std::string filename{};
};

class TestEvent final : public Event
{
public:
  static constexpr Type eventType = Type::kTest;

  virtual ~TestEvent() = default;
  virtual Type GetType() const
  {
    return eventType;
  }
};

class SaveEvent final : public Event
{
public:
  static constexpr Type eventType = Type::kSave;

  virtual ~SaveEvent() = default;
  virtual Type GetType() const
  {
    return eventType;
  }
};

class LoadEvent final : public Event
{
public:
  static constexpr Type eventType = Type::kLoad;

  virtual ~LoadEvent() = default;
  virtual Type GetType() const
  {
    return eventType;
  }
};

class CloseEvent final : public Event
{
public:
  static constexpr Type eventType = Type::kClose;

  virtual ~CloseEvent() = default;
  virtual Type GetType() const
  {
    return eventType;
  }
};

class EventDispatcher final
{
public:
  using Execution = std::function<void(const Event&)>;

  void Subscribe(const Event::Type& aEventType, Execution&& aExecution);

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
  std::unordered_map<Event::Type, std::vector<Execution>> observers;
};
