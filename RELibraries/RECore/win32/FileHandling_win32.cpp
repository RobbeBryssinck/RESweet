#include "../FileHandling.h"

// TODO: ifdef WIN32

#include <Windows.h>
#include <ShObjIdl.h>
#include <locale>
#include <codecvt>
#include <memory>

std::string OpenFileDialogue(const std::string* apcDialogueName, FileFilters* apcFilters)
{
  std::string filePath = "";

  std::vector<std::pair<std::wstring, std::wstring>> wideFilters{};

  std::unique_ptr<COMDLG_FILTERSPEC[]> pFilters;
  if (apcFilters)
  {
    pFilters = std::make_unique<COMDLG_FILTERSPEC[]>(apcFilters->size());

    std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
    for (size_t i = 0; i < apcFilters->size(); i++)
    {
      auto& filter = (*apcFilters)[i];
      auto& wideFilter = wideFilters.emplace_back();

      wideFilter.first = converter.from_bytes(filter.first);
      wideFilter.second = converter.from_bytes(filter.second);

      pFilters[i] = COMDLG_FILTERSPEC{wideFilter.first.c_str(), wideFilter.second.c_str()};
    }
  }

  HRESULT hResult = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);
  if (SUCCEEDED(hResult))
  {
    IFileOpenDialog* pFileOpen;

    hResult = CoCreateInstance(CLSID_FileOpenDialog, NULL, CLSCTX_ALL, IID_IFileOpenDialog, reinterpret_cast<void**>(&pFileOpen));
    if (SUCCEEDED(hResult))
    {
      if (pFilters)
        pFileOpen->SetFileTypes(wideFilters.size(), pFilters.get());

      if (apcDialogueName)
      {
        std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
        std::wstring dialogueName = converter.from_bytes(*apcDialogueName);
        pFileOpen->SetTitle(dialogueName.c_str());
      }

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
