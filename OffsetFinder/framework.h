#pragma once
#define WIN32_LEAN_AND_MEAN
// Windows Header Files
#include <windows.h>
#include <iostream>
#include <vector>
#include <memory>
#include <fstream>
#include <filesystem>
// Software Development Kit
#include "SDK/SDK.h"
using namespace SDK;

#define Log(...) \
printf(__VA_ARGS__);

const std::string outputPath = "C:\\Headers\\Addresses.h";
const std::string FuncsPath = "C:\\Headers\\Funcs.h";

static void BeginHeaderFile()
{
    std::filesystem::create_directories("C:\\Headers");

    std::ofstream file(outputPath, std::ios::trunc);
    if (!file) {
        std::cerr << "Failed to create header.\n";
        return;
    }

    file << "#pragma once\n\n";
    file << "namespace Addresses {\n";
    file.close();
}

static void BeginFuncsFile()
{
	std::filesystem::create_directories("C:\\Headers");

	std::ofstream file(FuncsPath, std::ios::trunc);
	if (!file) {
		std::cerr << "Failed to create header.\n";
		return;
	}

	file << "#pragma once\n\n";
	file << "inline uint64_t ImageBase = uint64_t(GetModuleHandle(0)); \n";
	file << "namespace Funcs {\n";
	file.close();
}

static void AppendFunc(const std::string& FuncName, const std::string ReturnValue, const std::string Arguments, std::string AddressName)
{
	std::ofstream file(FuncsPath, std::ios::app);
	if (!file) {
		std::cerr << "Failed to append to header.\n";
		return;
	}

	file << "    inline " << ReturnValue << " (*" << FuncName << ")" << "(" << Arguments << ")" << " = decltype(" << FuncName << ")" << "(ImageBase + "
		<< std::hex << std::uppercase << AddressName << ")" << ";\n";
	file.close();
}

static void Append(const std::string& varName, uint64_t Value, bool bWarning = false)
{
	std::ofstream file(outputPath, std::ios::app);
	if (!file) {
		std::cerr << "Failed to append to header.\n";
		return;
	}

	std::string AdditionalString = bWarning ? "//No Need to worry if this is 0x0" : "";

	file << "    inline uint64_t " << varName << " = 0x"
		<< std::hex << std::uppercase << Value << ";" << AdditionalString << "\n";
	file.close();
}

static void endHeader() {
    std::ofstream file(outputPath, std::ios::app);
    if (!file) {
        std::cerr << "Failed to finalize header.\n";
        return;
    }

    file << "}\n";
    file.close();
}

static void EndFuncHeader()
{
	std::ofstream file(FuncsPath, std::ios::app);
	if (!file) {
		std::cerr << "Failed to finalize header.\n";
		return;
	}

	file << "}\n";
	file.close();
}

namespace Offsets
{
	inline uintptr_t GIsClient;
	inline uintptr_t WorldGetNetMode;
	inline uintptr_t ActorNetMode;
	inline uintptr_t GameSessionIdPatch;
	inline uintptr_t KickPlayer;
	inline uintptr_t NetDriverSetWorld;
	inline uintptr_t NetDriverInitListen;
	inline uintptr_t NetDriverGetNetMode;
	inline uintptr_t NetDriverTickFlush;
	inline uintptr_t RepDriverServerReplicateActors;
	inline uintptr_t LocalPlayerSpawnPlayActor;
	inline uintptr_t EngineCreateNetDriver;
	inline uintptr_t StaticLoadObject;
	inline uintptr_t GetWorldContextFromObject;
	inline uintptr_t CreateNetDriverLocal;
	inline uintptr_t SendRequestNow;
	inline uintptr_t ApplyCharacterCustomization;
}



static void FindGIsClient()
{
	Memcury::Scanner Scanner = Memcury::Scanner::FindPattern("38 05 ? ? ? ? 0F 95 C0 FF C0");
	if (Scanner.Get() == 0)
	{
		Scanner = Memcury::Scanner::FindPattern("88 1D ? ? ? ? 45 8A EC", true);
	}
	Offsets::GIsClient = Scanner.RelativeOffset(2).Get();
}
static void FindWorldGetNetMode()
{
	Memcury::Scanner Scanner = Memcury::Scanner::FindPattern("E8 ? ? ? ? 48 8B BC 24 ? ? ? ? 33 C0 48 81 C4");
	if (Scanner.Get() == 0)
	{
		if (std::floor(SDK::UE::GetFortniteVersion()) == 18)
		{
			Offsets::WorldGetNetMode = Memcury::Scanner::FindPattern("48 83 EC 28 48 83 79 ? ? 75 20 48 8B 91 ? ? ? ? 48 85 D2 74 1E 48 8B 02 48 8B CA FF 90").Get();
		}
		else
		{
			Offsets::WorldGetNetMode = Memcury::Scanner::FindPattern("E9 ? ? ? ? E9 ? ? ? ? B8 ? ? ? ? C3", true).ScanFor({ 0x48 }, false, 3).Get();
		}
	}
	else
	{
		Offsets::WorldGetNetMode = Scanner.ScanFor({ 0x40, 0x53 }, false).Get();
	}
}
static void FindActorNetMode()
{
	if (std::floor(SDK::UE::GetFortniteVersion()) == 19)
	{
		Offsets::ActorNetMode = Memcury::Scanner::FindPattern("48 89 5C 24 ? 57 48 83 EC ? F6 41 ? ? 48 8B D9 0F 85 ? ? ? ? 48 8B 41 ? 48 85 C0 0F 84 ? ? ? ? F7 40 ? ? ? ? ? 0F 85", true).Get();
		return;
	}
	Offsets::ActorNetMode = Memcury::Scanner::FindPattern("E9 ? ? ? ? 48 85 FF 74 ? 48 8B 8F", true).ScanFor({ 0x48,0x89, 0x5C }, false).Get();
}
static void FindGameSessionIdPatch()
{
	if (std::floor(SDK::UE::GetFortniteVersion()) == 19)
	{
		Offsets::GameSessionIdPatch = Memcury::Scanner::FindPattern("48 89 5C 24 ? 55 56 57 41 54 41 55 41 56 41 57 48 8B EC 48 83 EC ? 4C 8B FA 48 8B F1 E8", true).Get();
		return;
	}
	Offsets::GameSessionIdPatch = Memcury::Scanner::FindStringRef(L"Changing GameSessionId from '%s' to '%s'").ScanFor({ 0x40, 0x55 }, false).Get();
}
static void FindKickPlayer()
{
	if (round(SDK::UE::GetFortniteVersion()) == 18)
	{
		Offsets::KickPlayer = Memcury::Scanner::FindPattern("48 8B C4 48 89 58 08 48 89 70 10 48 89 78 18 4C 89 60 20 55 41 56 41 57 48 8B EC 48 83 EC 60 48 83 65 ? ? 4C 8B F2 83 65 E8 00 4C 8B E1 83 65 EC").Get();
	}
	else
	{
		Offsets::KickPlayer = Memcury::Scanner::FindPattern("E8 ? ? ? ? 41 B0 ? 33 D2 48 8B CB E8 ? ? ? ? B0", true).ScanFor({ 0x48, 0x89, 0x5C }, false).Get();
	}
}
static void FindNetDriverSetWorld()
{
	if (round(SDK::UE::GetFortniteVersion()) == 18)
	{
		Offsets::NetDriverSetWorld = __int64(SDK::StaticClassImpl("NetDriver")->GetDefaultObj()->VTable[0x73]);
		return;
	}
	if (round(SDK::UE::GetFortniteVersion()) == 19)
	{
		Offsets::NetDriverSetWorld = __int64(SDK::StaticClassImpl("NetDriver")->GetDefaultObj()->VTable[0x7A]);
	}
	else if (SDK::UE::GetEngineVersion() >= 4.26)
		Offsets::NetDriverSetWorld = Memcury::Scanner::FindPattern("40 55 56 41 56 48 8B EC 48 83 EC ? 48 89 5C 24", true).Get();
	else
	{
		Offsets::NetDriverSetWorld = Memcury::Scanner::FindStringRef(L"AOnlineBeaconHost::InitHost failed", true).ScanFor({ 0xE8 }, false, 1).RelativeOffset(1).Get();
	}
}
static void FindNetDriverInitListen()
{
	if (SDK::UE::GetFortniteVersion() >= 19.00)
	{
		Offsets::NetDriverInitListen = Memcury::Scanner::FindPattern("E8 ? ? ? ? 48 8B 4C 24 ? 48 85 C9 74 ? E8 ? ? ? ? 32 C0 EB ? 48 8B 03", true).ScanFor({ 0x4C, 0x8B,0xDC }, false).Get();
		return;
	}
	Offsets::NetDriverInitListen = Memcury::Scanner::FindStringRef(L"Failed to init net driver ListenURL: %s: %s", true).ScanFor({ 0x48, 0x89,0x5C }, false).Get();
}
static void FindNetDriverGetNetMode()
{
	Offsets::NetDriverGetNetMode = Memcury::Scanner::FindPattern("E9 ? ? ? ? 48 85 FF 74 ? 48 8B 8F").RelativeOffset(2).Get();
}
static void FindNetDriverTickFlush()
{
	std::vector<uint8_t> Bytes = (SDK::UE::GetFortniteVersion() >= 19.00) ? std::vector<uint8_t>{0x48, 0x8B, 0xC4} : std::vector<uint8_t>{ 0x4C, 0x8B, 0xDC };
	Offsets::NetDriverTickFlush = Memcury::Scanner::FindStringRef(L"STAT_NetTickFlush").ScanFor(Bytes, false).Get();
}

static void FindRepDriverServerReplicateActors()
{
	std::vector<uint8_t> Bytes = (SDK::UE::GetFortniteVersion() >= 19.00) ? std::vector<uint8_t>({ 0x48,0x8B,0xC4 }) : std::vector<uint8_t>({ 0x4C, 0x8B, 0xDC });
	if (SDK::UE::GetFortniteVersion() <= 4.50) {
		Offsets::RepDriverServerReplicateActors = Memcury::Scanner::FindPattern(
			"4C 8B DC 55 49 8D AB ? ? ? ? 48 81 EC ? ? ? ? 48 8B 05 ? ? ? ? 48 33 C4 48 89 85 ? ? ? ? 48 8B 41 ? 49 89 5B ? 49 89 73 ? 49 89 7B").Get();
		return;
	}
		
	Offsets::RepDriverServerReplicateActors = Memcury::Scanner::FindStringRef(L"NET_PrepareReplication", true).ScanFor(Bytes, false).Get();
}

static void FindLocalPlayerSpawnPlayActor()
{
	Memcury::Scanner Scanner = Memcury::Scanner::FindPattern("48 89 5C 24 ? 48 89 74 24 ? 48 89 7C 24 ? 55 41 56 41 57 48 8D 6C 24 ? 48 81 EC ? ? ? ? 48 8B D9 4D 8B F1");
	if (Scanner.Get() == 0)
	{
		Scanner = Memcury::Scanner::FindPattern("40 55 53 56 57 41 56 41 57 48 8D AC 24 ? ? ? ? 48 81 EC ? ? ? ? 48 8B 05 ? ? ? ? 48 33 C4 48 89 85 ? ? ? ? 48 8B D9");
	}
	Offsets::LocalPlayerSpawnPlayActor = Scanner.Get();
}

static void FindEngineCreateNetDriver()
{
	Memcury::Scanner Scanner = Memcury::Scanner::FindPattern("E8 ? ? ? ? 48 89 87 ? ? ? ? 48 85 C0 0F 84 ? ? ? ? 48 89 5C 24 ? 48 8D 05");

	if (!Scanner.Get())
		Scanner = Memcury::Scanner::FindPattern("E8 ? ? ? ? 48 89 86 ? ? ? ? 48 85 C0 0F 84 ? ? ? ? 48 89 5C 24 ? 48 8D 05");

	Offsets::EngineCreateNetDriver = Scanner.Get() ? Scanner.RelativeOffset(1).Get() : -1;
}

static void FindGetWorldContextFromObject()
{
	Memcury::Scanner Scanner = Memcury::Scanner::FindPattern("E8 ? ? ? ? 48 85 C0 75 ? E8 ? ? ? ? 4C 8B C3 48 8B D0 48 8B CE");
	if (Scanner.Get())
		Offsets::GetWorldContextFromObject = Scanner.RelativeOffset(1).Get();
}

static void FindCreateNetDriverLocal()
{
	Memcury::Scanner Scanner = Memcury::Scanner::FindPattern("E8 ? ? ? ? 48 89 87 ? ? ? ? 48 85 C0 74 ? 83 64 24 ? ? 48 8D 05");
	if (Scanner.Get())
		Offsets::CreateNetDriverLocal = Scanner.RelativeOffset(1).Get();
}

static void FindSendRequestNow()
{
	Offsets::SendRequestNow = Memcury::Scanner::FindStringRef(L"MCP-Profile: Dispatching request to %s").ScanFor({ 0x48,0x89,0x5C }, false).Get();
}

static void FindApplyCharacterCustomization()
{
	Memcury::Scanner Scanner = Memcury::Scanner::FindPattern("48 8B C4 48 89 50 ? 55 57 48 8D 68 ? 48 81 EC ? ? ? ? 80 B9");
	Offsets::ApplyCharacterCustomization = Scanner.Get();

	if (!Offsets::ApplyCharacterCustomization)
	{
		SDK::UFunction* UpdatePlayerCustomCharacterPartsVisualization = (SDK::UFunction*)SDK::UE::Core::GObjects->FindObjectFast("UpdatePlayerCustomCharacterPartsVisualization");
		if (!UpdatePlayerCustomCharacterPartsVisualization)
			return void(Offsets::ApplyCharacterCustomization = -1);
		Scanner = Memcury::Scanner::FindPattern("E8 ? ? ? ? 44 0F B6 E0 EB ? 33 F6");

		if (!Scanner.Get())
		{
			Scanner = Memcury::Scanner::FindPattern("E8 ? ? ? ? E9 ? ? ? ? FF 90 ? ? ? ? 49 8B CE");
		}

		Offsets::ApplyCharacterCustomization = Scanner.RelativeOffset(1).Get();
	}
}

static void FindAll()
{
	FindGIsClient();
	FindWorldGetNetMode();
	FindActorNetMode();
	FindGameSessionIdPatch();
	FindKickPlayer();
	FindNetDriverSetWorld();
	FindNetDriverInitListen();
	FindNetDriverGetNetMode();
	FindNetDriverTickFlush();
	FindRepDriverServerReplicateActors();
	FindLocalPlayerSpawnPlayActor();
	FindEngineCreateNetDriver();
	FindGetWorldContextFromObject();
	FindCreateNetDriverLocal();
	FindSendRequestNow();
	FindApplyCharacterCustomization();
}

static bool HasValidate(UFunction* Func)
{
	std::string ValidateString = Func->GetName().ToString() += "_Validate";
	return Memcury::Scanner::FindStringRef(ValidateString).Get() != 0;
}

static int GetFunctionIdx(UFunction* Func)
{
	int VirtualFuncIdx = 0;
	bool bHasValidate = HasValidate(Func);
	if (bHasValidate)
	{
		VirtualFuncIdx = *Memcury::Scanner(Func->Func()).ScanFor({ 0xFF, 0x90 }, true, 1).AbsoluteOffset(2).GetAs<int*>();
	}
	else
	{
		VirtualFuncIdx = *Memcury::Scanner(Func->Func()).ScanFor({ 0xFF, 0x90 }).AbsoluteOffset(2).GetAs<int*>();
	}

	return (VirtualFuncIdx / 8);
}

static uint64 GetFunctionAddress(const char* ClassName, const char* FunctionName)
{
	UClass* Class = StaticClassImpl(ClassName + 1);

	UFunction* Function = Class->FindFunctionByName(FunctionName);

	int Index = GetFunctionIdx(Function);

	uint64 Address = uint64(Class->GetDefaultObj()->VTable[Index]) - SDK::UE::Memory::GetBaseAddress();
	return Address;
}