#include "DebuggingDetector.h"
#include "Windows.h"
#include <iostream>


DebuggingDetector::DebuggingDetector()
{
}

// Checks if there are any hardware breakpoint set
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

// Function used for the flow redirection on hooks to kill the process
void DebuggerDetectedExit()
{
	std::cout << "Debugger attach detected!";
	ExitProcess(1);
}

// Exception Handler for hardware breakpoint hooks
LONG WINAPI MyExceptionHandler(PEXCEPTION_POINTERS pExceptionInfo)
{
	DebuggerDetectedExit();
	//return EXCEPTION_CONTINUE_SEARCH;
}

// Adds hooks on functions with breakpoints which are triggered on debugger attach
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

// Detects if anti-attach hooks have been deleted
bool DebuggingDetector::DeletedDebuggerAttachHooks()
{
	HMODULE ntdll_handle = GetModuleHandle(L"ntdll.dll");
	PVOID hooks[2] = { GetProcAddress(ntdll_handle, "DbgBreakPoint"), GetProcAddress(ntdll_handle, "DbgUiRemoteBreakin") };

	for (int i = 0; i < 2; i++) {
		BYTE* h = (BYTE*)hooks[i];
		if (h[0] != 0x48 || h[1] != 0xB8) {
			return true;
		}
	}

	return false;
}

// it is the same implementation of IsDebuggerPresent, but not using the Windows API to avoid breakpoint detection
bool DebuggingDetector::IsDebuggerPresent()
{
	BYTE* PEB = (BYTE*)__readgsqword(0x60);
	// printf("PEB: %p ; Debugger: %d\n", PEB, PEB[2]);
	return PEB[2];
}

// Opens the binary in restricted shared mode (3rd parameter of CreateFile); if another process has the file open it will fail
// the binary could have been open by debugger, disassembler, etc.
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

// Sets hardware breakpoints on execution for different functions (actually is not really useful)
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

