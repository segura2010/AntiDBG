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

	ULONG oldProtection;

	VirtualProtect(pDbgBreakPoint, 20, PAGE_EXECUTE_READWRITE, &oldProtection);
	WriteProcessMemory(GetCurrentProcess(), pDbgBreakPoint, jmp, sizeof(jmp), NULL);
	DWORD64 jmpOffset = (DWORD64)((DWORD64)DebuggerDetectedExit - (DWORD64)pDbgBreakPoint) - 5;
	WriteProcessMemory(GetCurrentProcess(), (PVOID)((DWORD64)pDbgBreakPoint + 1), &jmpOffset, sizeof(jmpOffset), NULL);
	VirtualProtect(pDbgBreakPoint, 20, oldProtection, &oldProtection);

	VirtualProtect(pDbgUiRemoteBreakin, 20, PAGE_EXECUTE_READWRITE, &oldProtection);
	WriteProcessMemory(GetCurrentProcess(), pDbgUiRemoteBreakin, jmp, sizeof(jmp), NULL);
	jmpOffset = (DWORD64)((DWORD64)DebuggerDetectedExit - (DWORD64)pDbgUiRemoteBreakin) - 5;
	WriteProcessMemory(GetCurrentProcess(), (PVOID)((DWORD64)pDbgUiRemoteBreakin + 1), &jmpOffset, sizeof(jmpOffset), NULL);
	VirtualProtect(pDbgUiRemoteBreakin, 20, oldProtection, &oldProtection);
}

void DebuggingDetector::KillDebuggerAttachHWBP()
{
	// It will use Hardware Breakpoint to "hook"; do not use the HWBP detector once you call this function
	HMODULE ntdll_handle = GetModuleHandle(L"ntdll.dll");
	PVOID pDbgBreakPoint = GetProcAddress(ntdll_handle, "DbgBreakPoint");
	PVOID pDbgUiRemoteBreakin = GetProcAddress(ntdll_handle, "DbgUiRemoteBreakin");
	HMODULE kernel32_handle = GetModuleHandle(L"kernel32.dll");
	PVOID pIsDebuggerPresent = GetProcAddress(kernel32_handle, "IsDebuggerPresent");

	// set exception handler which will be executed on HWBP
	AddVectoredExceptionHandler(1, MyExceptionHandler);
	SetUnhandledExceptionFilter(MyExceptionHandler);

	HANDLE hThread = GetCurrentThread();
	CONTEXT ctx;
	ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
	if (GetThreadContext((HANDLE)-2, &ctx)) {
		ctx.Dr0 = (DWORD64)pDbgBreakPoint;
		ctx.Dr1 = (DWORD64)pDbgUiRemoteBreakin;
		ctx.Dr2 = (DWORD64)pIsDebuggerPresent;
		ctx.Dr3 = 0;
		ctx.Dr7 = (1 << 0) | (1 << 2) | (1 << 4); // set breakpoint on execution
		SetThreadContext(hThread, &ctx);
	}
	CloseHandle(hThread);
}

