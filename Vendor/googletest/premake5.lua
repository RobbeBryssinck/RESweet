project "googletest"
    kind "StaticLib"
    language "C++"

    files
    {
        "src/**.h",
        "src/**.cc",
        "include/**.h",
    }

    includedirs
    {
        "include",
        "./"
    }
