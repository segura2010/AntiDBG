// AntiDBG.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include "Windows.h"
#include "DebuggingDetector.h"

int main()
{
    DebuggingDetector dd = DebuggingDetector();
    if (dd.CheckHWBP(true) || dd.IsDebuggerPresent() || dd.CheckIfBinaryOpened()) {
        std::cout << "Debugger detected !!" << std::endl;
        return 0;
    }
    dd.KillDebuggerAttach();
    dd.KillDebuggerAttachHWBP();
    std::cout << "Hello World!\n";

    int wait;
    std::cin >> wait;
}
