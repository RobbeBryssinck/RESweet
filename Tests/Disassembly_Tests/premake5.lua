group("Tests")
project "Disassembly_Tests"
   kind "ConsoleApp"
   language "C++"

   files {"**.h", "**.cpp", "../main.cpp"}

   includedirs 
   {
      "../../Components",
      "../../Vendor/googletest/include",
      "../../Vendor/capstone/include",
      "../../RELibraries/RECore"
   }

   libdirs
   {
      "../Build/Bin/%{cfg.longname}",
      "../../Vendor/capstone"
   }

   links "googletest"
   links "Disassembly"
   links "BinLoader"