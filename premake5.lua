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

function includeCapstone()
   includedirs "Vendor/capstone/include"
end

function linkCapstone()
   libdirs "Vendor/capstone"

   filter "kind:not StaticLib"
      links "capstone"
   filter {}
end

project "BinLoader"
   kind "StaticLib"
   language "C++"
   targetdir "bin/%{cfg.buildcfg}"

   files "Components/BinLoader/**"


   includedirs 
   {
      "Vendor/spdlog/include"
   }

   includeCapstone()

project "UnderTheHood"
   kind "ConsoleApp"
   language "C++"
   targetdir "bin/%{cfg.buildcfg}"

   files "UnderTheHood/**"

   includedirs 
   {
      "Components/BinLoader",
      "Vendor/spdlog/include"
   }
   links "BinLoader"

   includeCapstone()
   linkCapstone()