#include <Windows.h>

void ThreadProc(){
	MessageBox(0, 0, 0, 0);
}

void Entry(){
	HANDLE hThread = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)ThreadProc, 0, 0, 0);
	WaitForSingleObject(hThread, INFINITE);
	CloseHandle(hThread);
}