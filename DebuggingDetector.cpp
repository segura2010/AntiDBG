#include "DebuggingDetector.h"
#include "Windows.h"
#include <iostream>


DebuggingDetector::DebuggingDetector()
{
}

bool DebuggingDetector::CheckHWBP(bool disable)
{
	bool active = false;
	HANDLE hThread = GetCurrentThread();
	CONTEXT ctx;
	ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
	if (GetThreadContext((HANDLE) -2, &ctx)) {
		if (ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3) {
			active = true;
			if (disable) {
				ctx.Dr0 = 0;
				ctx.Dr1 = 0;
				ctx.Dr2 = 0;
				ctx.Dr3 = 0;
				SetThreadContext(hThread, &ctx);
			}
		}
	}
	CloseHandle(hThread);
	return active;
}


void DebuggerDetectedExit()
{
	std::cout << "Debugger attach detected!";
	ExitProcess(1);
}

LONG WINAPI MyExceptionHandler(PEXCEPTION_POINTERS pExceptionInfo)
{
	DebuggerDetectedExit();
	//return EXCEPTION_CONTINUE_SEARCH;
}

void DebuggingDetector::KillDebuggerAttach()
{
	// It will use Hardware Breakpoint to "hook"; do not use the HWBP detector once you call this function
	HMODULE ntdll_handle = GetModuleHandle(L"ntdll.dll");
	PVOID pDbgBreakPoint = GetProcAddress(ntdll_handle, "DbgBreakPoint");
	PVOID pDbgUiRemoteBreakin = GetProcAddress(ntdll_handle, "DbgUiRemoteBreakin");
	
	BYTE jmp[1] = { 0xE9 };
	BYTE movRAX[2] = { 0x48, 0xB8 };
	BYTE pushRAX_ret[2] = { 0x50, 0xC3 };

	ULONG oldProtection;
	DWORD64 pDebuggerDetectedExit = (DWORD64)DebuggerDetectedExit;

	VirtualProtect(pDbgBreakPoint, 20, PAGE_EXECUTE_READWRITE, &oldProtection);
	WriteProcessMemory(GetCurrentProcess(), pDbgBreakPoint, movRAX, sizeof(movRAX), NULL);
	WriteProcessMemory(GetCurrentProcess(), (PVOID)((DWORD64)pDbgBreakPoint + 2), &pDebuggerDetectedExit, sizeof(DWORD64), NULL);
	WriteProcessMemory(GetCurrentProcess(), (PVOID)((DWORD64)pDbgBreakPoint + 10), pushRAX_ret, sizeof(pushRAX_ret), NULL);
	VirtualProtect(pDbgBreakPoint, 20, oldProtection, &oldProtection);

	VirtualProtect(pDbgUiRemoteBreakin, 20, PAGE_EXECUTE_READWRITE, &oldProtection);
	WriteProcessMemory(GetCurrentProcess(), pDbgUiRemoteBreakin, movRAX, sizeof(movRAX), NULL);
	WriteProcessMemory(GetCurrentProcess(), (PVOID)((DWORD64)pDbgUiRemoteBreakin + 2), &pDebuggerDetectedExit, sizeof(DWORD64), NULL);
	WriteProcessMemory(GetCurrentProcess(), (PVOID)((DWORD64)pDbgUiRemoteBreakin + 10), pushRAX_ret, sizeof(pushRAX_ret), NULL);
	VirtualProtect(pDbgUiRemoteBreakin, 20, oldProtection, &oldProtection);
}

bool DebuggingDetector::IsDebuggerPresent()
{
	BYTE* PEB = (BYTE*)__readgsqword(0x60);
	// printf("PEB: %p ; Debugger: %d\n", PEB, PEB[2]);
	return PEB[2];
}

bool DebuggingDetector::CheckIfBinaryOpened()
{
	wchar_t modulename[MAX_PATH];
	GetModuleFileName(GetModuleHandle(NULL), modulename, MAX_PATH);
	HANDLE f = CreateFile(modulename, GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
	bool is_open = f == INVALID_HANDLE_VALUE;
	if (!is_open) {
		CloseHandle(f);
	}
	return is_open;
}

void DebuggingDetector::KillDebuggerAttachHWBP()
{
	// It will use Hardware Breakpoint to "hook"; do not use the HWBP detector once you call this function
	HMODULE ntdll_handle = GetModuleHandle(L"ntdll.dll");
	PVOID pDbgUiRemoteBreakin = GetProcAddress(ntdll_handle, "DbgUiRemoteBreakin");
	HMODULE kernel32_handle = GetModuleHandle(L"kernel32.dll");
	HMODULE kernelbase_handle = GetModuleHandle(L"kernelbase.dll");
	PVOID pVirtualProtect = GetProcAddress(kernelbase_handle, "VirtualProtect");
	PVOID pIsDebuggerPresent = GetProcAddress(kernel32_handle, "IsDebuggerPresent");

	// set exception handler which will be executed on HWBP
	AddVectoredExceptionHandler(1, MyExceptionHandler);
	SetUnhandledExceptionFilter(MyExceptionHandler);

	HANDLE hThread = GetCurrentThread();
	CONTEXT ctx;
	ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
	if (GetThreadContext((HANDLE)-2, &ctx)) {
		ctx.Dr0 = (DWORD64)pVirtualProtect;
		ctx.Dr1 = (DWORD64)pDbgUiRemoteBreakin;
		ctx.Dr2 = (DWORD64)pIsDebuggerPresent;
		ctx.Dr3 = 0;
		ctx.Dr7 = (1 << 0) | (1 << 2) | (1 << 4); // set breakpoint on execution
		SetThreadContext(hThread, &ctx);
	}
	CloseHandle(hThread);
}

