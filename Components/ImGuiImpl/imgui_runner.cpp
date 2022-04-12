// Dear ImGui: standalone example application for DirectX 11
// If you are new to Dear ImGui, read documentation from the docs/ folder + read the top of imgui.cpp.
// Read online: https://github.com/ocornut/imgui/tree/master/docs

#include "imgui.h"
#include "imgui_impl_glfw.h"
#include "imgui_impl_opengl3.h"
#include "imgui_runner.h"
#include <spdlog/spdlog.h>
#include <d3d11.h>
#include <tchar.h>
#include <locale>
#include <codecvt>

static bool s_closeApplication = false;

imgui_runner::imgui_runner(const std::string& acString)
{
  std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
  std::wstring wide = converter.from_bytes(acString);
  const wchar_t* pWide = wide.c_str();

  // Create application window
  wc = { sizeof(WNDCLASSEX), CS_CLASSDC, WndProc, 0L, 0L, GetModuleHandle(NULL), NULL, NULL, NULL, NULL, wide.c_str(), NULL};
  ::RegisterClassEx(&wc);
  hwnd = ::CreateWindow(wc.lpszClassName, wide.c_str(), WS_OVERLAPPEDWINDOW, 100, 100, 1280, 800, NULL, NULL, wc.hInstance, NULL);

  // Initialize Direct3D
  if (!CreateDeviceD3D(hwnd))
  {
      CleanupDeviceD3D();
      ::UnregisterClass(wc.lpszClassName, wc.hInstance);
      return;
  }

  // Show the window
  ::ShowWindow(hwnd, SW_MAXIMIZE);
  ::UpdateWindow(hwnd);

  // Setup Dear ImGui context
  IMGUI_CHECKVERSION();
  ImGui::CreateContext();
  ImGuiIO& io = ImGui::GetIO(); (void)io;
  io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;       // Enable Keyboard Controls
  io.ConfigFlags |= ImGuiConfigFlags_DockingEnable;           // Enable Docking
  io.ConfigFlags |= ImGuiConfigFlags_ViewportsEnable;         // Enable Multi-Viewport / Platform Windows

  // Setup Dear ImGui style
  ImGui::StyleColorsDark();

  // When viewports are enabled we tweak WindowRounding/WindowBg so platform windows can look identical to regular ones.
  ImGuiStyle& style = ImGui::GetStyle();
  if (io.ConfigFlags & ImGuiConfigFlags_ViewportsEnable)
  {
      style.WindowRounding = 0.0f;
      style.Colors[ImGuiCol_WindowBg].w = 1.0f;
  }

  // Setup Platform/Renderer backends
  ImGui_ImplWin32_Init(hwnd);
  ImGui_ImplDX11_Init(g_pd3dDevice, g_pd3dDeviceContext);
}

imgui_runner::~imgui_runner()
{
  // Cleanup
  ImGui_ImplDX11_Shutdown();
  ImGui_ImplWin32_Shutdown();
  ImGui::DestroyContext();

  CleanupDeviceD3D();
  ::DestroyWindow(hwnd);
  ::UnregisterClass(wc.lpszClassName, wc.hInstance);
}

bool imgui_runner::BeginFrame()
{
  MSG msg;
  while (::PeekMessage(&msg, NULL, 0U, 0U, PM_REMOVE))
  {
    ::TranslateMessage(&msg);
    ::DispatchMessage(&msg);
  }

  if (s_closeApplication)
    return false;

  ImGui_ImplDX11_NewFrame();
  ImGui_ImplWin32_NewFrame();
  ImGui::NewFrame();

  return true;
}

void imgui_runner::EndFrame()
{
  ImGuiIO& io = ImGui::GetIO(); (void)io;
  ImVec4 clear_color = ImVec4(0.45f, 0.55f, 0.60f, 1.00f);

  // Rendering
  ImGui::Render();
  const float clear_color_with_alpha[4] = { clear_color.x * clear_color.w, clear_color.y * clear_color.w, clear_color.z * clear_color.w, clear_color.w };
  g_pd3dDeviceContext->OMSetRenderTargets(1, &g_mainRenderTargetView, NULL);
  g_pd3dDeviceContext->ClearRenderTargetView(g_mainRenderTargetView, clear_color_with_alpha);
  ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());

  // Update and Render additional Platform Windows
  if (io.ConfigFlags & ImGuiConfigFlags_ViewportsEnable)
  {
      ImGui::UpdatePlatformWindows();
      ImGui::RenderPlatformWindowsDefault();
  }

  g_pSwapChain->Present(1, 0); // Present with vsync
  //g_pSwapChain->Present(0, 0); // Present without vsync
}
