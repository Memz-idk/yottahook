#include "yottahook.h"
#include <stdio.h>
typedef int (WINAPI *fpMessageBoxA)(HWND hwnd, const char* text, const char* caption, unsigned int type);
fpMessageBoxA gMessageBoxA;

int WINAPI hkMessageBoxA(HWND hwnd, const char* text, const char* caption, unsigned int type) {
	puts("msg");
	return gMessageBoxA(hwnd, "Hooked", caption, type);
}

int main(void) {
	for(;;) {
		YH_Hook(MessageBoxA, hkMessageBoxA, (void*)&gMessageBoxA);
		MessageBoxA(NULL, "Unhooked", "YottaHook", MB_OK);
		YH_Unhook(MessageBoxA, gMessageBoxA);
		MessageBoxA(NULL, "Unhooked", "YottaHook", MB_OK);
	}
}