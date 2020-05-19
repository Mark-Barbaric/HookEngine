// HookEngineTest.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <Windows.h>
#include <cstdlib>
#include <tchar.h>

BOOL(__cdecl* HookFunction)(ULONG_PTR OriginalFunction, ULONG_PTR NewFunction);
VOID(__cdecl* UnhookFunction)(ULONG_PTR Function);
ULONG_PTR(__cdecl* GetOriginalFunction)(ULONG_PTR Hook);

int WINAPI MyMessageBoxW(HWND hend, LPCWSTR lpTest, LPCWSTR lpCaption,
	UINT uType, WORD wLanguageId, DWORD dwMilliseconds);

int APIENTRY _tWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance,
	LPTSTR lpCmdLine, int nCmdShow)
{
	//===========================================================
	// Hook Functions

	HMODULE hHookEngineDll = LoadLibrary(L"HookEngineDLL.dll");

	HookFunction = (BOOL(__cdecl*)(ULONG_PTR, ULONG_PTR))
		GetProcAddress(hHookEngineDll, "HookFunction");

	UnhookFunction = (VOID(__cdecl*)(ULONG_PTR))
		GetProcAddress(hHookEngineDll, "UnhookFunction");

	GetOriginalFunction = (ULONG_PTR(__cdecl*)(ULONG_PTR))
		GetProcAddress(hHookEngineDll, "GetOriginalFunction");

	if (HookFunction == NULL || UnhookFunction == NULL ||
		GetOriginalFunction == NULL)
		return 0;

	//===========================================================
	// Hook MessageBoxTimeoutW

	HookFunction((ULONG_PTR)GetProcAddress(LoadLibrary(L"User32.dll"),
		"MessageBoxTimeoutW"),
		(ULONG_PTR)&MyMessageBoxW);

	MessageBoxW(0, L"Hi, this is a message box!", L"This is the title.",
		MB_ICONINFORMATION);

	//===========================================================
	// Unhook MessageBoxTimeoutW

	UnhookFunction((ULONG_PTR)GetProcAddress(LoadLibrary(L"User32.dll"),
		"MessageBoxTimeoutW"));


	MessageBoxW(0, L"Hi, this is a message box!", L"This is the title.",
		MB_ICONINFORMATION);

	return 0;
}

int WINAPI MyMessageBoxW(HWND hWnd, LPCWSTR lpText, LPCWSTR lpCaption, UINT uType,
	WORD wLanguageId, DWORD dwMilliseconds)
{
	int (WINAPI * pMessageBoxW)(HWND hWnd, LPCWSTR lpText,
		LPCWSTR lpCaption, UINT uType, WORD wLanguageId,
		DWORD dwMilliseconds);

	pMessageBoxW = (int (WINAPI*)(HWND, LPCWSTR, LPCWSTR, UINT, WORD, DWORD))
		GetOriginalFunction((ULONG_PTR)MyMessageBoxW);

	return pMessageBoxW(hWnd, lpText, L"Hooked MessageBox",
		uType, wLanguageId, dwMilliseconds);
}