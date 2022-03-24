workspace "RESweet"
   location "Generated"

   architecture "x64"
   configurations { "Debug", "Release" }

   cppdialect "C++20"

   filter { "configurations:Debug" }
      defines { "DEBUG" }
      symbols "On"

   filter { "configurations:Release" }
      defines { "NDEBUG" }
      optimize "On"

   targetdir ("Build/Bin/%{prj.name}/%{cfg.longname}")
   objdir ("Build/Obj/%{prj.name}/%{cfg.longname}")

include("Vendor")
include("Components")
include("UnderTheHood")