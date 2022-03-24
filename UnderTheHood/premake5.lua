group("Core")
project "UnderTheHood"
   kind "ConsoleApp"
   language "C++"
   targetdir "bin/%{cfg.buildcfg}"

   files {"**.h", "**.cpp"}

   includedirs 
   {
      "../Components",
      "../Vendor/spdlog/include",
      "../Vendor/capstone/include"
   }

   libdirs
   {
      "../Vendor/capstone"
   }

   links "BinLoader"
   links "ImGuiImpl"
   links "capstone"