#include "DisassemblyWindow.h"

#include "../Application.h"

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
  Application::Get().GetDispatcher().Subscribe(Event::Type::kOpenFile, std::bind(&DisassemblyWindow::OnOpenFile, this, std::placeholders::_1));
  Application::Get().GetDispatcher().Subscribe(Event::Type::kLoad, std::bind(&DisassemblyWindow::OnLoad, this, std::placeholders::_1));
  Application::Get().GetDispatcher().Subscribe(Event::Type::kSave, std::bind(&DisassemblyWindow::OnSave, this, std::placeholders::_1));
}

void DisassemblyWindow::Update()
{
  static bool show = false;
  ImGui::ShowDemoWindow(&show);

  ImGui::Begin("Disassembly");

  count += 1;

  ImGui::Text("Count: %d", count);

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

void DisassemblyWindow::OnOpenFile(const Event& aEvent)
{
  RE_ASSERT(aEvent.GetType() == Event::Type::kOpenFile);

  const OpenFileEvent& fileEvent = static_cast<const OpenFileEvent&>(aEvent);

  fileToDisassemble = fileEvent.filename;

  std::shared_ptr<Binary> pBinary = Parsing::ParseFile(fileToDisassemble);

  if (pBinary)
    functions = Disassembly::Disassemble(pBinary);
  else
    fileToDisassemble = "";
}

void DisassemblyWindow::OnLoad(const Event& aEvent)
{
  RE_ASSERT(aEvent.GetType() == Event::Type::kLoad);

  const LoadEvent& loadEvent = static_cast<const LoadEvent&>(aEvent);

  LoadFromFile(loadEvent.filename);
}

void DisassemblyWindow::OnSave(const Event& aEvent)
{
  RE_ASSERT(aEvent.GetType() == Event::Type::kSave);

  SaveToFile();
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

  SaveManager& saveManager = Application::Get().GetSaveManager();
  saveManager.SetFilePath(std::filesystem::path(fileToDisassemble));

  std::filesystem::path filePath(fileToDisassemble);
  std::string filename = filePath.filename().string();

  saveManager.resf.header.filename = filename;

  saveManager.resf.functions.reserve(functions.size());
  for (auto& [address, function] : functions)
  {
    auto& savedFunction = saveManager.resf.functions.emplace_back();

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

  saveManager.isDisassemblyReady = true;
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
