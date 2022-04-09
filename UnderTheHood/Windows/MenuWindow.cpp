#include "MenuWindow.h"

#include "../Application.h"

#include <FileHandling.h>

#include <imgui.h>

void MenuWindow::Setup()
{

}

void MenuWindow::Update()
{
  ImGui::Begin("Menu");

  if (ImGui::Button("Open file"))
    Application::Get().GetDispatcher().Dispatch(OpenFileEvent(OpenFileDialogue()));

  ImGui::End();
}
