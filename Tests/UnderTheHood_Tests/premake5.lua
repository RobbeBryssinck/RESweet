group("Tests")
project "UnderTheHood_Tests"
   kind "ConsoleApp"
   language "C++"

   files {"**.h", "**.cpp", "../main.cpp"}

   includedirs 
   {
      "../../UnderTheHood",
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