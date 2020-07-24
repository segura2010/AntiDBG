#pragma once
class DebuggingDetector
{
public:
	DebuggingDetector();

	bool CheckHWBP(bool disable);
	void KillDebuggerAttach();
	bool DeletedDebuggerAttachHooks();
	bool IsDebuggerPresent();
	bool CheckIfBinaryOpened();

	void KillDebuggerAttachHWBP();

private:

};

