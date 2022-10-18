project "ImGuiImpl"
   kind "StaticLib"
   language "C++"

   files {"**.h", "**.cpp", "**.inl"}

   includedirs 
   {
      "../../Vendor/imgui",
      "../../Vendor/spdlog/include"
   }

   links "imgui"