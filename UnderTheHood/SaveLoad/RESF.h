#pragma once

#include <Reader.h>
#include <Writer.h>

#include <cstdint>
#include <string>
#include <vector>
#include <filesystem>

class SaveManager
{
public:
  bool IsReadyToSave() const
  {
    return isDisassemblyReady &&
           isStringsReady;
  }

  bool SetFilePath(const std::filesystem::path& aPath)
  {
    file = aPath;
  }

  bool Save();

  RESF resf{};
  std::filesystem::path file{};
  bool isDisassemblyReady = false;
  bool isStringsReady = false;
};

struct RESF
{
  struct Header
  {
    void Serialize(Writer& aWriter) const;
    void Deserialize(Reader& aReader);

    uint32_t magic = 'FSER';
    std::string filename{};
  };

  struct SavedInstruction
  {
    void Serialize(Writer& aWriter) const;
    void Deserialize(Reader& aReader);

    uint32_t id{};
    uint64_t address{};
    uint16_t size{};
    uint8_t bytes[16]{};
    char mnemonic[32]{};
    char operand[160]{};
  };

  struct SavedFunction
  {
    void Serialize(Writer& aWriter) const;
    void Deserialize(Reader& aReader);

    uint64_t address{};
    std::string name{};
    std::vector<SavedInstruction> instructions{};
  };

  void Serialize(Writer& aWriter) const;
  void Deserialize(Reader& aReader);

  Header header{};
  std::vector<SavedFunction> functions{};
  std::vector<std::string> strings{};
};
