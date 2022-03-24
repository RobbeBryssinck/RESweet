group("Apps")
project "UnderTheHood"
   kind "ConsoleApp"
   language "C++"

   files {"**.h", "**.cpp"}

   includedirs 
   {
      "../Components",
      "../Vendor/spdlog/include",
      "../Vendor/capstone/include"
   }

   libdirs
   {
      "../Build/Bin/%{cfg.longname}",
      "../Vendor/capstone"
   }

   links "BinLoader"
   links "d3d11"
   links "imgui"
   links "ImGuiImpl"
   links "capstone"