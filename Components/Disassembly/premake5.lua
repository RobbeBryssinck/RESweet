project "Disassembly"
   kind "StaticLib"
   language "C++"

   files {"**.h", "**.cpp", "**.inl"}

   includedirs 
   {
      "../../Vendor/spdlog/include",
      "../../Vendor/capstone/include",
      "../BinLoader"
   }

   libdirs
   {
      "../../Vendor/capstone"
   }

   links "BinLoader"
   links "capstone"