// dllmain.cpp : Defines the entry point for the DLL application.

#include <Windows.h>
#include <cstdlib>
#include "distorm.h"

constexpr int MAX_HOOKS = 1000;
constexpr bool RELATIVE_JUMPS = false;

typedef struct _HOOK_INFO
{
    ULONG_PTR Function; //Address of original function
    ULONG_PTR Hook; // Address of function to call
    ULONG_PTR Bridge; // Address of instruction bridge needed for the hook jmp which overrites instructions
} HOOK_INFO, *PHOOK_INFO;

HOOK_INFO HookInfo[MAX_HOOKS];
UINT NumberOfHooks = 0;
BYTE* pBridgeBuffer = nullptr;
UINT CurrentBridgeBufferSize = 0;

#ifdef _M_IX86
#define JUMP_WORST 10
#else ifdef _M_AMD64
#define JUMP_WORST 14
#endif


BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
	    {
			pBridgeBuffer = (BYTE*) VirtualAlloc(nullptr, MAX_HOOKS * (JUMP_WORST * 3),
            MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	    }
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

HOOK_INFO* GetHookInfoFromFunction(ULONG_PTR OriginalFunction)
{
    if (NumberOfHooks == 0)
        return nullptr;

	for(UINT x = 0; x < NumberOfHooks; x++)
	{
        if (HookInfo[x].Function == OriginalFunction)
            return &HookInfo[x];
	}

    return nullptr;
}

UINT GetJumpSize(ULONG_PTR PosA, ULONG_PTR PosB)
{
	//Relative Jumps
    //ULONG_PTR res = max(PosA, PosB) - min(PosA, PosB);
	//To Do
	//
#ifdef _M_IX86
    return 10;
#else ifdef _M_AMD64
    return 14;
#endif
    //}
    return 0; // error
}

VOID WriteJump(VOID* pAddress, ULONG_PTR JumpTo)
{
    DWORD dwOldProtect = 0;
    VirtualProtect(pAddress, JUMP_WORST, PAGE_EXECUTE_READWRITE, &dwOldProtect);
    BYTE* pCur = static_cast<BYTE*>(pAddress);


#ifdef _M_IX86

    *pCur = 0xff; //jmp [addr]
    *(++pCur) = 0x25;
    pCur++;
    *reinterpret_cast<DWORD*>(pCur) = reinterpret_cast<ULONG_PTR>(pCur) +sizeof(DWORD);
    pCur += sizeof(DWORD);
    *reinterpret_cast<ULONG_PTR*> (pCur) = JumpTo;

#else ifdef _M_AND64

    *pCur = 0xff; //jmp [addr]
    *(++pCur) = 0x25;
    *reinterpret_cast<DWORD*>(++pCur) = 0;
    pCur += sizeof(DWORD);
    *reinterpret_cast<ULONG_PTR*>(pCur) = JumpTo;
	
#endif
	
    DWORD dwBuf = 0;
    VirtualProtect(pAddress, JUMP_WORST, dwOldProtect, &dwBuf);
}

PVOID CreateBridge(ULONG_PTR Function, const UINT JumpSize)
{
    if (pBridgeBuffer == nullptr) return nullptr;

#define MAX_INSTRUCTIONS 100

    _DecodeResult res;
    _DecodedInst decodedInstructions[MAX_INSTRUCTIONS];
    unsigned int decodedInstructionsCount = 0;

#ifdef _M_IX86

    _DecodeType dt = Decode32Bits;

#else ifdef _M_AMD64

    _DecodeType dt = Decode64Bits;

#endif

    _OffsetType offset = 0;
    res = distorm_decode(offset, //offset for buffer
        reinterpret_cast<const BYTE*>(Function), //buffer to disassemble
        50, //function size (50 instr should be enough) 
        dt, //x86 or X64
        decodedInstructions, //decoded instr
        MAX_INSTRUCTIONS, //array size
        &decodedInstructionsCount); //how many instr were disassembled
    
    if (res == DECRES_INPUTERR)return nullptr;

    DWORD InstrSize = 0;
    PVOID pBridge = reinterpret_cast<PVOID>(&pBridgeBuffer[CurrentBridgeBufferSize]);

    for (UINT x = 0; x < decodedInstructionsCount; x++)
    {
        if (InstrSize >= JumpSize) break;

        BYTE* pCurInstr = reinterpret_cast<BYTE*>(InstrSize + (ULONG_PTR)Function);
        memcpy(&pBridgeBuffer[CurrentBridgeBufferSize], reinterpret_cast<PVOID>(pCurInstr), decodedInstructions[x].size);
        CurrentBridgeBufferSize += decodedInstructions[x].size;
        InstrSize += decodedInstructions[x].size;
    }

    WriteJump(&pBridgeBuffer[CurrentBridgeBufferSize], Function + InstrSize);
    CurrentBridgeBufferSize += GetJumpSize(reinterpret_cast<ULONG_PTR>(&pBridgeBuffer[CurrentBridgeBufferSize]),
        Function + InstrSize);

    return pBridge;
}

//============================================================================================
//Function Hooks
extern "C" __declspec(dllexport)
BOOL __cdecl HookFunction(ULONG_PTR OriginalFunction, ULONG_PTR NewFunction)
{
    HOOK_INFO* hInfo = GetHookInfoFromFunction(OriginalFunction);

    if (hInfo)
    {
        WriteJump(reinterpret_cast<PVOID>(OriginalFunction), NewFunction);
    }
    else
    {
        if (NumberOfHooks == (MAX_HOOKS - 1)) return FALSE;

        PVOID pBridge = CreateBridge(OriginalFunction, GetJumpSize(OriginalFunction, NewFunction));

        if (pBridge == nullptr) return FALSE;

        HookInfo[NumberOfHooks].Function = OriginalFunction;
        HookInfo[NumberOfHooks].Bridge = reinterpret_cast<ULONG_PTR>(pBridge);
        HookInfo[NumberOfHooks].Hook = NewFunction;
        NumberOfHooks++;
        WriteJump(reinterpret_cast<PVOID>(OriginalFunction), NewFunction);
    }

    return TRUE;
}

extern "C" __declspec(dllexport)
VOID __cdecl UnhookFunction(ULONG_PTR Function)
{
    HOOK_INFO* hInfo = GetHookInfoFromFunction(Function);
    // Check if the function has already been hooked
	// If not, I can't unhook it

    if (hInfo)
    {
        // Replaces the hook jump with a jump to the bridge
        // Not completely unhooking since I'm not
        // restoring the original bytes
        WriteJump(reinterpret_cast<PVOID>(hInfo->Function), hInfo->Bridge);	
    }
}

extern "C" __declspec(dllexport)
ULONG_PTR __cdecl GetOriginalFunction(ULONG_PTR Hook)
{
    if (NumberOfHooks == 0) return NULL;

    for (UINT x = 0; x < NumberOfHooks; x++)
    {
        if (HookInfo[x].Hook == Hook)
            return HookInfo[x].Bridge;
    }

    return NULL;
}