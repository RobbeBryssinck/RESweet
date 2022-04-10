#include "RESF.h"

#include "../Application.h"

bool SaveManager::Save()
{
  if (!IsReadyToSave())
    return false;

  Writer writer{};
  resf.Serialize(writer);

  writer.WriteToFile(file.parent_path().string() + "\\" + file.filename().string() + ".resf");

  resf = RESF();
  isDisassemblyReady = isStringsReady = false;

  return true;
}

void RESF::Header::Serialize(Writer& aWriter) const
{
  aWriter.Write(magic);
  aWriter.WriteString(filename);
}

void RESF::Header::Deserialize(Reader& aReader)
{
  aReader.Read(magic);
  filename = aReader.ReadString();
}

void RESF::SavedInstruction::Serialize(Writer& aWriter) const
{
  aWriter.Write(*this);
}

void RESF::SavedInstruction::Deserialize(Reader& aReader)
{
  aReader.Read(*this);
}

void RESF::SavedFunction::Serialize(Writer& aWriter) const
{
  aWriter.Write(address);
  aWriter.WriteString(name);

  const size_t instructionCount = instructions.size();
  aWriter.Write(instructionCount);

  for (const SavedInstruction& instruction : instructions)
    instruction.Serialize(aWriter);
}

void RESF::SavedFunction::Deserialize(Reader& aReader)
{
  aReader.Read(address);
  name = aReader.ReadString();

  size_t instructionCount = 0;
  aReader.Read(instructionCount);

  for (size_t i = 0; i < instructionCount; i++)
  {
    SavedInstruction& instruction = instructions.emplace_back();
    instruction.Deserialize(aReader);
  }
}

void RESF::Serialize(Writer& aWriter) const
{
  header.Serialize(aWriter);

  const size_t functionCount = functions.size();
  aWriter.Write(functionCount);

  for (const SavedFunction& function : functions)
    function.Serialize(aWriter);

  const size_t stringCount = strings.size();
  aWriter.Write(stringCount);

  for (const std::string& string : strings)
    aWriter.WriteString(string);
}

void RESF::Deserialize(Reader& aReader)
{
  header.Deserialize(aReader);

  size_t functionCount = 0;
  aReader.Read(functionCount);

  for (size_t i = 0; i < functionCount; i++)
  {
    SavedFunction& function = functions.emplace_back();
    function.Deserialize(aReader);
  }

  size_t stringCount = 0;
  aReader.Read(stringCount);

  for (size_t i = 0; i < stringCount; i++)
    strings.push_back(std::move(aReader.ReadString()));
}
