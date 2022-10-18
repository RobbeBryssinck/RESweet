project "ImGuiImpl"
   kind "StaticLib"
   language "C++"

   files {"**.h", "**.cpp", "**.inl"}

   includedirs 
   {
      "../../Vendor/imgui",
      "../../Vendor/spdlog/include",
      "../../Vendor/glfw/include"
   }

   links "imgui"
   links "glfw"
   links "opengl32.lib"
