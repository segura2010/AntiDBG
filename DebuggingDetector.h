#pragma once
class DebuggingDetector
{
public:
	DebuggingDetector();

	bool CheckHWBP(bool disable);
	void KillDebuggerAttach();

private:

};
