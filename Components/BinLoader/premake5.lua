project "BinLoader"
   kind "StaticLib"
   language "C++"
   targetdir "bin/%{cfg.buildcfg}"

   files {"**.h", "**.cpp", "**.inl"}

   includedirs 
   {
      "../../Vendor/spdlog/include"
   }