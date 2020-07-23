// AntiDBG.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include "Windows.h"
#include "DebuggingDetector.h"

int main()
{
    DebuggingDetector dd = DebuggingDetector();
    if (dd.CheckHWBP(true) || dd.IsDebuggerPresent()) {
        std::cout << "Debugger detected !!" << std::endl;
        return 0;
    }
    dd.KillDebuggerAttach();
    std::cout << "Hello World!\n";
    
    //IsDebuggerPresent();

    int wait;
    std::cin >> wait;
}
