# RESweet
A suite of sweet RE tools.

# Building
To build, simply pull the repository recursively, and use the premake binary (which is supplied with the repo) to generate project files and build as you normally would with premake. Here is an example workflow for Windows.

## Setting up the environment and building on Windows
Make sure you have Visual Studio 2022 installed, along with the appropriate VS C++ modules. Pull the git repository recursively and generate the project files with the following command:

```cmd
> git clone --recursive https://github.com/RobbeBryssinck/RESweet.git
> cd RESweet/
> ./GenerateSolution.bat
```

The solution file can be found in `./Generated/`. The application can be built through Visual Studio.
