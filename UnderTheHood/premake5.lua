group("Apps")
project "UnderTheHood"
   kind "ConsoleApp"
   language "C++"

   files {"**.h", "**.cpp"}

   includedirs 
   {
      "../Components",
      "../Vendor/spdlog/include",
      "../Vendor/capstone/include",
      "../RELibraries/RECore",
      "../Vendor/imgui"
   }

   libdirs
   {
      "../Build/Bin/%{cfg.longname}",
      "../Vendor/capstone"
   }

   links "RECore"
   links "BinLoader"
   links "Disassembly"
   links "d3d11"
   links "imgui"
   links "ImGuiImpl"