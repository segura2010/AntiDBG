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

LONG WINAPI MyExceptionHandler(PEXCEPTION_POINTERS pExceptionInfo)
{
	std::cout << "Debugger attach detected!";
	ExitProcess(1);
	//return EXCEPTION_CONTINUE_SEARCH;
}

void DebuggingDetector::KillDebuggerAttach()
{
	// It will use Hardware Breakpoint to "hook"; do not use the HWBP detector once you call this function
	HMODULE ntdll_handle = GetModuleHandle(L"ntdll.dll");
	PVOID pDbgBreakPoint = GetProcAddress(ntdll_handle, "DbgBreakPoint");

	// set exception handler which will be executed on HWBP
	AddVectoredExceptionHandler(1, MyExceptionHandler);
	SetUnhandledExceptionFilter(MyExceptionHandler);

	HANDLE hThread = GetCurrentThread();
	CONTEXT ctx;
	ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
	if (GetThreadContext((HANDLE)-2, &ctx)) {
		ctx.Dr0 = 0;
		ctx.Dr1 = 0;
		ctx.Dr2 = 0;
		ctx.Dr3 = (DWORD64)pDbgBreakPoint;
		ctx.Dr7 = (1 << 0) | (1 << 2) | (1 << 4); // set breakpoint on execution
		SetThreadContext(hThread, &ctx);
	}
	CloseHandle(hThread);
}

