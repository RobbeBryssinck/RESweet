project "BinLoader"
   kind "StaticLib"
   language "C++"
   targetdir "bin/%{cfg.buildcfg}"

   files {"**.h", "**.cpp"}

   includedirs 
   {
      "../../Vendor/spdlog/include"
   }