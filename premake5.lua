workspace "RESweet"
   location "Generated"

   architecture "x64"
   configurations { "Debug", "Release" }

   filter { "configurations:Debug" }
      defines { "DEBUG" }
      symbols "On"

   filter { "configurations:Release" }
      defines { "NDEBUG" }
      optimize "On"

   targetdir ("Build/Bin/%{prj.name}/%{cfg.longname}")
   objdir ("Build/Obj/%{prj.name}/%{cfg.longname}")

project "BinLoader"
   kind "StaticLib"
   language "C++"
   targetdir "bin/%{cfg.buildcfg}"

   files "Components/BinLoader/**"

function includeCapstone()
   includedirs "Vendor/capstone/include"
end

function linkCapstone()
   filter "kind:not StaticLib"
      links "capstone"
   filter {}
end

project "UnderTheHood"
   kind "ConsoleApp"
   language "C++"
   targetdir "bin/%{cfg.buildcfg}"

   files "UnderTheHood/**"

   includedirs "Components/BinLoader"
   links "BinLoader"

   includeCapstone()
   linkCapstone()