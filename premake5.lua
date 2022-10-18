workspace "RESweet"
   location "Generated"

   architecture "x64"
   configurations { "Debug", "Release" }

   filter "system:windows"
      defines { "NOMINMAX" }
      cppdialect "C++20"

   filter "system:linux"
      cppdialect "C++2a"

   filter { "configurations:Debug" }
      defines { "DEBUG" }
      symbols "On"

   filter { "configurations:Release" }
      defines { "NDEBUG" }
      optimize "On"

   filter { }

   targetdir ("Build/Bin/%{cfg.longname}")
   objdir ("Build/Obj")

include("Vendor")
include("RELibraries")
include("Components")
include("UnderTheHood")
include("Playground")
include("Tests")
