project "ImGuiImpl"
   kind "StaticLib"
   language "C++"
   targetdir "bin/%{cfg.buildcfg}"

   files {"**.h", "**.cpp", "**.inl"}

   includedirs 
   {
      "../../Vendor/imgui"
   }

   libdirs
   {
      "../../Vendor/imgui/bin"
   }

   links "imgui"