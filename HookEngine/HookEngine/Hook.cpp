
#include "../../distorm/include/distorm.h"
#include <Windows.h>
#include <cstdio>

#pragma comment(lib, "../../distorm/build/temp.win-amd64-3.9/Release/python/_distorm3.cp39-win_amd64.lib")

DWORD RvaToOffset(PIMAGE_NT_HEADERS nt, DWORD rva);
VOID AddFunctionToLog(FILE* log, BYTE* fileBuffer, DWORD functionRVA);
VOID GetInstructionString(char* Str, _DecodedInst* Instr);

int _tmain(int argc, WCHAR* argv[])
{
	if (argc < 2)
		return 0;

	FILE* log = nullptr;

	if (_wfopen_s(&log, argv[2], L"w") != 0)
		return 0;

	HANDLE hFile = CreateFile(argv[1], GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);

	if (hFile == INVALID_HANDLE_VALUE)
		return 0;

	DWORD fileSize = GetFileSize(hFile, nullptr);
	BYTE* fileBuffer = new BYTE[fileSize];
	DWORD brw;

	if (fileBuffer)
		ReadFile(hFile, fileBuffer, fileSize, &brw, nullptr);

	CloseHandle(hFile);

	PIMAGE_DOS_HEADER pDosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(fileBuffer);
	PIMAGE_NT_HEADERS pNtHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>((fileBuffer != nullptr ? pDosHeader->e_lfanew : 0) + reinterpret_cast<ULONG_PTR>(fileBuffer));

	if(!fileBuffer || pDosHeader->e_magic != IMAGE_DOS_SIGNATURE || pNtHeaders->Signature != IMAGE_NT_SIGNATURE || pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress == 0)
	{
		fclose(log);

		if (fileBuffer)
		{
			delete[] fileBuffer;
			fileBuffer = nullptr;
			
		}
	}

	DWORD ET_RVA = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	PIMAGE_EXPORT_DIRECTORY pExportDir = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(RvaToOffset(pNtHeaders, ET_RVA) + reinterpret_cast<ULONG_PTR>(fileBuffer));
	DWORD* pFunctions = reinterpret_cast<DWORD*>((RvaToOffset(pNtHeaders,
		pExportDir->AddressOfFunctions)) + reinterpret_cast<ULONG_PTR>(fileBuffer));

	for (DWORD x = 0; x < pExportDir->NumberOfFunctions; x++)
	{
		if (pFunctions[x] == 0) continue;
		AddFunctionToLog(log, fileBuffer, pFunctions[x]);
	}
	
	fclose(log);
	delete[] fileBuffer;
	fileBuffer = nullptr;
	
	return 0;
}

VOID AddFunctionToLog(FILE* log, BYTE* fileBuffer, DWORD functionRVA)
{
#define MAX_INSTRUCTIONS 100
	PIMAGE_NT_HEADERS pNtHeaders =
		reinterpret_cast<PIMAGE_NT_HEADERS>(((*(PIMAGE_DOS_HEADER)fileBuffer).e_lfanew + reinterpret_cast<ULONG_PTR>(fileBuffer)));
	_DecodeResult res;
	_DecodedInst decodedInstructions[MAX_INSTRUCTIONS];
	unsigned int decodedInstructionsCount = 0;
#ifdef _M_IX86
	_DecodeType dt = Decode32Bits;
#define JUMP_SIZE 10
#else ifdef _M_AMD64
	_DecodeType dt = Decode64Bits;
#define JUMP_SIZE 14 // worst case scenario
#endif

	_OffsetType offset = 0;
	res = distorm_decode(offset,
		(const BYTE*)&fileBuffer[RvaToOffset(pNtHeaders, functionRVA)],
		50,
		dt,
		decodedInstructions,
		MAX_INSTRUCTIONS,
		&decodedInstructionsCount);

	if (res == DECRES_INPUTERR)
		return;

	DWORD instrSize = 0;

	for(UINT x = 0; x < decodedInstructionsCount; x++)
	{
		if (instrSize >= JUMP_SIZE)
			break;

		instrSize += decodedInstructions[x].size;
		char instr[100];
		GetInstructionString(instr, &decodedInstructions[x]);
		fwprintf(log, L"%s \n", instr);
	}
	
}

VOID GetInstructionString(wchar_t* Str, _DecodedInst* Instr)
{
	wsprintfW(Str, L"%s %s", Instr->mnemonic.p, Instr->operands.p);
	_wcslwr_s(Str, 100);
}

DWORD RvaToOffset(PIMAGE_NT_HEADERS nt, DWORD rva)
{
	DWORD offset = rva, limit;
	PIMAGE_SECTION_HEADER img;
	WORD i;
	img = IMAGE_FIRST_SECTION(nt);

	if (rva < img->PointerToRawData)
		return rva;

	for(i = 0; i < nt->FileHeader.NumberOfSections; ++i)
	{
		if (img[i].SizeOfRawData)
			limit = img[i].SizeOfRawData;
		else
			limit = img[i].Misc.VirtualSize;

		if(rva >= img[i].VirtualAddress && rva < (img[i].VirtualAddress + limit))
		{
			if (img[i].PointerToRawData != 0)
			{
				offset -= img[i].VirtualAddress;
				offset += img[i].PointerToRawData;
			}
			return offset;
		}
	}

	return NULL;
}