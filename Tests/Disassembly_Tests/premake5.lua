group("Tests")
project "Disassembly_Tests"
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

   links "googletest"
   links "Disassembly"