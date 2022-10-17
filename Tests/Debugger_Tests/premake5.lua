group("Tests")
project "Debugger_Tests"
   kind "ConsoleApp"
   language "C++"

   files {"**.h", "**.cpp", "../main.cpp"}

   includedirs 
   {
      "../../Components/Debugger",
      "../../RELibraries/RECore",
      "../../Vendor/spdlog/include",
      "../../Vendor/googletest/include"
   }

   libdirs
   {
      "../Build/Bin/%{cfg.longname}"
   }

   links "googletest"
   links "RECore"
   links "Debugger"