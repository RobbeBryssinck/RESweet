group("Tests")
project "BinLoader_Tests"
   kind "ConsoleApp"
   language "C++"

   files {"**.h", "**.cpp", "../main.cpp"}

   includedirs 
   {
      "../../Components",
      "../../Vendor/googletest/include",
      "../../RELibraries/RECore"
   }

   libdirs
   {
      "../Build/Bin/%{cfg.longname}"
   }

   links "BinLoader"
   links "googletest"