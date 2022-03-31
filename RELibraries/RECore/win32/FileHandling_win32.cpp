#include "../FileHandling.h"

// TODO: ifdef WIN32

#include <Windows.h>
#include <ShObjIdl.h>

std::string OpenFileDialogue()
{
  std::string filePath = "";

  HRESULT hResult = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);
  if (SUCCEEDED(hResult))
  {
    IFileOpenDialog* pFileOpen;

    hResult = CoCreateInstance(CLSID_FileOpenDialog, NULL, CLSCTX_ALL, IID_IFileOpenDialog, reinterpret_cast<void**>(&pFileOpen));
    if (SUCCEEDED(hResult))
    {
      hResult = pFileOpen->Show(NULL);

      if (SUCCEEDED(hResult))
      {
        IShellItem* pItem;
        hResult = pFileOpen->GetResult(&pItem);
        if (SUCCEEDED(hResult))
        {
          PWSTR pszFilePath;
          hResult = pItem->GetDisplayName(SIGDN_FILESYSPATH, &pszFilePath);

          if (SUCCEEDED(hResult))
          {
            // TODO: barf
            char filePathBuf[256];
            wcstombs(filePathBuf, pszFilePath, sizeof(filePathBuf));

            filePath = filePathBuf;

            CoTaskMemFree(pszFilePath);
          }
          pItem->Release();
        }
      }
      pFileOpen->Release();
    }
    CoUninitialize();
  }

  return filePath;
}

