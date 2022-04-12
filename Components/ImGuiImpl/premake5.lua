project "ImGuiImpl"
   kind "StaticLib"
   language "C++"

   files {"**.h", "**.cpp", "**.inl"}

   includedirs 
   {
      "../../Vendor/imgui",
      "../../Vendor/spdlog/include",
      "../../Vendor/GLFW/include"
   }

   libdirs
   {
      "../../Build/Bin/%{cfg.longname}"
   }

   links "imgui"
   links "GLFW"
   links "opengl32.lib"