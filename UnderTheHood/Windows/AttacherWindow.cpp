#include "AttacherWindow.h"

#include "../Application.h"

#include <imgui.h>
#include <spdlog/spdlog.h>

#include <Processes.h>

void AttacherWindow::Setup()
{
  Application::Get().GetDispatcher().Subscribe(Event::Type::kOpenFile, std::bind(&AttacherWindow::OnOpen, this, std::placeholders::_1));
  Application::Get().GetDispatcher().Subscribe(Event::Type::kLoad, std::bind(&AttacherWindow::OnOpen, this, std::placeholders::_1));
  Application::Get().GetDispatcher().Subscribe(Event::Type::kClose, std::bind(&AttacherWindow::OnClose, this, std::placeholders::_1));

  shown = false;
}

void AttacherWindow::Update()
{
  if (!shown)
    return;

  if (!ImGui::Begin("Debugger", &shown))
  {
    ImGui::End();
    return;
  }

  RenderError();

  if (ImGui::Button("Refresh list of processes"))
    InitListOfProcesses();

  if (!processes.empty() && !isDebugging)
  {
    std::unique_ptr<const char* []> items = std::make_unique<const char* []>(processes.size());
    for (int i = 0; i < processes.size(); i++)
      items[i] = processes[i].second.c_str();

    ImGui::PushItemWidth(-1);
    ImGui::ListBox("Processes", &currentProcess, items.get(), processes.size(), 20);
    ImGui::PopItemWidth();

    if (ImGui::Button("Debug"))
      isDebugging = debugger.AttachDebugger(processes[currentProcess].first);
  }
  else if (isDebugging)
  {
    const auto isDebugging = fmt::format("Is debugging? {}", debugger.IsDebugging());
    ImGui::Text(isDebugging.c_str());
  }

  ImGui::End();
}

void AttacherWindow::SetShown(bool aShow)
{
  Window::SetShown(aShow);

  Destroy();
  InitListOfProcesses();
}

void AttacherWindow::OnOpen(const Event& aEvent)
{
  RE_ASSERT(aEvent.GetType() == Event::Type::kOpenFile || aEvent.GetType() == Event::Type::kLoad);

  InitListOfProcesses();
}

void AttacherWindow::OnClose(const Event& aEvent)
{
  RE_ASSERT(aEvent.GetType() == Event::Type::kClose);

  Destroy();
}

void AttacherWindow::RenderError()
{
  switch (currentUIError)
  {
  case UIError::kProcessListingFailed:
    RenderProcessListError();
    break;
  case UIError::kNone:
    break;
  }
}

void AttacherWindow::RenderProcessListError()
{
  ImVec2 center = ImGui::GetMainViewport()->GetCenter();
  ImGui::SetNextWindowPos(center, ImGuiCond_Appearing, ImVec2(0.5f, 0.5f));

  if (ImGui::BeginPopupModal("Process list failed", NULL, ImGuiWindowFlags_AlwaysAutoResize))
  {
    ImGui::Text("Failed to load process list.");

    if (ImGui::Button("Close"))
    {
      currentUIError = UIError::kNone;
      ImGui::CloseCurrentPopup();
    }

    ImGui::EndPopup();
  }
}

void AttacherWindow::InitListOfProcesses()
{
  currentProcess = 0;

  auto result = GetListOfProcesses();
  if (!result)
    currentUIError = UIError::kProcessListingFailed;
  else
  {
    processes = *result;
    for (auto& process : processes)
      process.second = fmt::format("{} {}", process.first, process.second);
  }
}

void AttacherWindow::Destroy()
{
  processes.clear();
  currentProcess = 0;
  isDebugging = false;
}
