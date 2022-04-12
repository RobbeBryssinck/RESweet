group("Tests")
project "Strings_Tests"
   kind "ConsoleApp"
   language "C++"

   files {"**.h", "**.cpp"}

   includedirs 
   {
      "../../Components/Strings",
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