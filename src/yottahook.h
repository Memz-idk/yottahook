#pragma once
#include <stdint.h>
#include <stdlib.h>
#include <Windows.h>
#define JMP32 0xE9
#define JMP32_LEN 5

#if defined(_WIN32) || defined(_WIN64)
#if defined(_WIN64)
#define YH_Max(a, b) (((a) > (b)) ? (a) : (b))
#define YH_Min(a, b) (((a) < (b)) ? (a) : (b))
#define JMP64_LEN 14
#define JMP64_OP_LEN 6

inline void YH_FindNearbyMemory(void* target, SYSTEM_INFO* si, void** memory) {
	DWORD gran = si->dwAllocationGranularity;
	uintptr_t startAddr = (uintptr_t)target;
	startAddr -= startAddr % gran;
	uintptr_t minAddr = YH_Max(startAddr - 0x7FFFFFFF, (uintptr_t)si->lpMinimumApplicationAddress);
	uintptr_t maxAddr = YH_Min(startAddr + 0x7FFFFFFF, (uintptr_t)si->lpMaximumApplicationAddress);
	uintptr_t highAddr = startAddr - gran;
	uintptr_t lowAddr = startAddr - gran;
	MEMORY_BASIC_INFORMATION mbi;
	int memoryCount = 0;
	while(highAddr < maxAddr && lowAddr > minAddr) {
		VirtualQuery((void*)highAddr, &mbi, sizeof(mbi));
		if(mbi.State == MEM_FREE) {
			*memory = (void*)highAddr;
			break;
		}
		highAddr += gran;
		VirtualQuery((void*)lowAddr, &mbi, sizeof(mbi));
		if(mbi.State == MEM_FREE) {
			*memory = (void*)lowAddr;
			break;
		}
		lowAddr -= gran;
	}
}

inline void YH_Hook(void* src, void* dst, void** tramp) {
	SYSTEM_INFO si;
	GetSystemInfo(&si);
	void* trampAddr;
	YH_FindNearbyMemory(src, &si, &trampAddr);
	*tramp = VirtualAlloc(trampAddr, JMP32_LEN * 2 + JMP64_LEN, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	memcpy(*tramp, src, JMP32_LEN);
	*(byte*)((uintptr_t)*tramp + JMP32_LEN) = JMP32;
	*(uint32_t*)((uintptr_t)*tramp + JMP32_LEN + 1) = (uint32_t)((uintptr_t)src - (uintptr_t)*tramp) - JMP32_LEN;

	const byte JMP64[] = {0xFF, 0x25, 0x00, 0x00, 0x00, 0x00};
	memcpy((void*)((uintptr_t)*tramp + JMP32_LEN * 2), JMP64, JMP64_OP_LEN);
	*(uintptr_t*)((uintptr_t)*tramp + JMP32_LEN * 2 + JMP64_OP_LEN) = (uintptr_t)dst;

	DWORD oldProt;
	VirtualProtect(src, JMP32_LEN, PAGE_EXECUTE_READWRITE, &oldProt);
	*(byte*)src = JMP32;
	*(uint32_t*)((uintptr_t)src + 1) = (uint32_t)(((uintptr_t)*tramp + JMP32_LEN * 2) - (uintptr_t)src) - JMP32_LEN;
	VirtualProtect(src, JMP32_LEN, oldProt, &oldProt);
}

#else
inline void YH_Hook(void* src, void* dst, void** tramp) {
	*tramp = VirtualAlloc(NULL, JMP32_LEN * 2, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	memcpy(*tramp, src, JMP32_LEN);
	*(byte*)((uintptr_t)*tramp + JMP32_LEN) = JMP32;
	*(uintptr_t*)((uintptr_t)*tramp + JMP32_LEN + 1) = (uintptr_t)src - (uintptr_t)*tramp - JMP32_LEN;
	DWORD oldProt;
	VirtualProtect(src, JMP32_LEN, PAGE_EXECUTE_READWRITE, &oldProt);
	*(byte*)src = JMP32;
	*(uintptr_t*)((uintptr_t)src + 1) = (uintptr_t)dst - (uintptr_t)src - JMP32_LEN;
	VirtualProtect(src, JMP32_LEN, oldProt, &oldProt);
}
#endif
#else
#error "This is a Windows only header."
#endif
inline void YH_Unhook(void* func, void* tramp) {
	DWORD oldProt;
	VirtualProtect(func, JMP32_LEN, PAGE_EXECUTE_READWRITE, &oldProt);
	memcpy(func, tramp, JMP32_LEN);
	VirtualProtect(func, JMP32_LEN, oldProt, &oldProt);
	VirtualFree(tramp, 0, MEM_RELEASE);
}