function includeCapstone()
   includedirs "../Vendor/capstone/include"
end

function linkCapstone()
   libdirs "../Vendor/capstone"

   filter "kind:not StaticLib"
      links "capstone"
   filter {}
end

project "UnderTheHood"
   kind "ConsoleApp"
   language "C++"
   targetdir "bin/%{cfg.buildcfg}"

   files {"**.h", "**.cpp"}

   includedirs 
   {
      "../Components/BinLoader",
      "../Vendor/spdlog/include"
   }
   links "BinLoader"

   includeCapstone()
   linkCapstone()