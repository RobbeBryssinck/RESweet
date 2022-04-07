#include "DisassemblyWindow.h"

#include "../SaveLoad/RESF.h"

#include <BinLoader/BaseParser.h>
#include <FileHandling.h>

#include <imgui.h>
#include <spdlog/spdlog.h>

#include <filesystem>
#include <queue>
#include <set>

DisassemblyWindow::~DisassemblyWindow()
{
  Destroy();
}

void DisassemblyWindow::Setup()
{
  count = 0;
}

void DisassemblyWindow::Update()
{
  static bool show = false;
  //ImGui::ShowDemoWindow(&show);

  ImGui::Begin("Disassembly");

  count += 1;

  ImGui::Text("Count: %d", count);

  if (ImGui::Button("New"))
  {
    const std::string dialogueTitle = "Open file to disassemble";
    fileToDisassemble = OpenFileDialogue(&dialogueTitle);

    std::shared_ptr<Binary> pBinary = Parsing::ParseFile(fileToDisassemble);

    if (pBinary)
      functions = Disassembly::Disassemble(pBinary);
    else
      fileToDisassemble = "";
  }

  ImGui::SameLine();

  if (ImGui::Button("Load"))
  {
    FileFilters filters{ {"RESweet save file", "*.resf"} };
    const std::string dialogueTitle = "Open RESweet save file";
    const std::string fileToLoad = OpenFileDialogue(&dialogueTitle, &filters);

    LoadFromFile(fileToLoad);
  }

  if (IsDisassembled())
  {
    if (ImGui::Button("Save"))
      SaveToFile();

    ImGui::SameLine();

    if (ImGui::Button("Close"))
      Destroy();

    // Check again in case the "Close" button was clicked
    if (IsDisassembled())
    {
      ImGui::Text("Function count: %d", functions.size());

      static uint64_t address = 0;
      ImGui::InputScalar("Address", ImGuiDataType_U64, &address, 0, 0, "%" PRIx64, ImGuiInputTextFlags_CharsHexadecimal);
      if (ImGui::Button("Get function") && address)
      {
        auto functionIt = functions.find(address);
        if (functionIt == functions.end())
          spdlog::error("Function with address {:X} not found.", address);
        else
        {
          ImGui::OpenPopup(functionIt->second.name.c_str());
          modalFunction = functionIt->second;
        }
      }

      ImGui::Separator();

      for (const auto& function : functions)
      {
        if (ImGui::Button(function.second.name.c_str()))
        {
          ImGui::OpenPopup(function.second.name.c_str());
          modalFunction = function.second;
        }
      }
    }
  }

  if (modalFunction)
    RenderDisassemblyModal(modalFunction);

  ImGui::End();
}

void DisassemblyWindow::RenderDisassemblyModal(const Disassembly::Function& acFunction)
{
  ImVec2 center = ImGui::GetMainViewport()->GetCenter();
  ImGui::SetNextWindowPos(center, ImGuiCond_Appearing, ImVec2(0.5f, 0.5f));

  bool drawNewFunction = false;

  if (ImGui::BeginPopupModal(acFunction.name.c_str(), NULL, ImGuiWindowFlags_AlwaysAutoResize))
  {
    for (const cs_insn& instruction : acFunction.instructions)
    {
      std::string instructionString = BuildInstructionString(instruction);
      ImGui::Text(instructionString.c_str());
      if (ImGui::BeginPopupContextItem(instructionString.c_str()))
      {
        if (ImGui::Selectable("Copy instruction"))
        {
          ImGui::LogToClipboard();
          ImGui::LogText(instructionString.c_str());
          ImGui::LogFinish();
        }

        bool isCall = instruction.id == X86_INS_CALL;
        if (!isCall)
          ImGui::BeginDisabled();

        if (ImGui::Selectable("Go to function"))
        {
          // TODO: you should really make use of the detail struct of capstone
          // or, again, make your own instruction interface, since detail is allocated and that gets messy
          std::stringstream ss;
          ss << std::hex << instruction.op_str;
          uint64_t target = 0;
          ss >> target;

          if (target)
          {
            auto newFunctionIt = functions.find(target);

            if (newFunctionIt == functions.end())
              spdlog::error("Could not find function with address {:x}", target);
            else
            {
              modalFunction = newFunctionIt->second;
              drawNewFunction = true;
            }
          }
        }

        if (!isCall)
          ImGui::EndDisabled();

        ImGui::EndPopup();
      }

      if (drawNewFunction)
        break;
    }

    if (ImGui::Button("Close"))
    {
        ImGui::CloseCurrentPopup();
        modalFunction = Disassembly::Function{};
    }

    if (drawNewFunction)
        ImGui::CloseCurrentPopup();

    ImGui::EndPopup();
  }

  if (drawNewFunction)
    ImGui::OpenPopup(modalFunction.name.c_str());
}

void DisassemblyWindow::OnEvent(const Event& acEvent)
{

}

std::string DisassemblyWindow::BuildInstructionString(const cs_insn& apInstruction)
{
  std::string instructionString = fmt::format("{:#018x}: ", apInstruction.address);

  for (size_t j = 0; j < 16; j++)
  {
    if (j < apInstruction.size)
      instructionString += fmt::format("{:02x} ", apInstruction.bytes[j]);
    else
      instructionString += "   ";
  }

  instructionString += fmt::format("{:<12}{}\n", apInstruction.mnemonic, apInstruction.op_str);

  return instructionString;
}

void DisassemblyWindow::SaveToFile() const
{
  if (fileToDisassemble == "")
    return;

  RESF resf{};

  std::filesystem::path filePath(fileToDisassemble);
  std::string filename = filePath.filename().string();

  resf.header.filename = filename;

  resf.functions.reserve(functions.size());
  for (auto& [address, function] : functions)
  {
    auto& savedFunction = resf.functions.emplace_back();

    savedFunction.address = address;
    savedFunction.name = function.name;

    savedFunction.instructions.reserve(function.instructions.size());
    for (auto& instruction : function.instructions)
    {
      auto& savedInstruction = savedFunction.instructions.emplace_back();

      savedInstruction.id = instruction.id;
      savedInstruction.address = instruction.address;
      savedInstruction.size = instruction.size;

      std::copy(std::begin(instruction.bytes), std::end(instruction.bytes), std::begin(savedInstruction.bytes));
      std::copy(std::begin(instruction.mnemonic), std::end(instruction.mnemonic), std::begin(savedInstruction.mnemonic));
      std::copy(std::begin(instruction.op_str), std::end(instruction.op_str), std::begin(savedInstruction.operand));
    }
  }

  Writer writer{};
  resf.Serialize(writer);

  writer.WriteToFile(filePath.parent_path().string() + "\\" + filename + ".resf");
}

void DisassemblyWindow::LoadFromFile(const std::string& acFilename)
{
  Destroy();

  Reader reader{};
  if (!reader.LoadFromFile(acFilename))
    return;

  RESF resf{};
  resf.Deserialize(reader);

  std::filesystem::path filePath(resf.header.filename);
  fileToDisassemble = filePath.string();

  functions.reserve(resf.functions.size());
  for (auto& savedFunction : resf.functions)
  {
    auto& function = functions[savedFunction.address];

    function.address = savedFunction.address;
    function.name = savedFunction.name;

    function.instructions.reserve(savedFunction.instructions.size());
    for (auto& savedInstruction : savedFunction.instructions)
    {
      auto& instruction = function.instructions.emplace_back();

      instruction.id = savedInstruction.id;
      instruction.address = savedInstruction.address;
      instruction.size = savedInstruction.size;

      std::copy(std::begin(savedInstruction.bytes), std::end(savedInstruction.bytes), std::begin(instruction.bytes));
      std::copy(std::begin(savedInstruction.mnemonic), std::end(savedInstruction.mnemonic), std::begin(instruction.mnemonic));
      std::copy(std::begin(savedInstruction.operand), std::end(savedInstruction.operand), std::begin(instruction.op_str));
    }
  }
}

void DisassemblyWindow::Destroy()
{
  fileToDisassemble = "";
  functions.clear();
  modalFunction = Disassembly::Function{};
}
