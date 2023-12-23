#pragma once
#include <Windows.h>
//void GetFileContent(LPCSTR filepath);
LPVOID GetFileContent(LPCSTR szInjectedFile) {
	HANDLE hFile;
	if (!(hFile = CreateFileA(
		szInjectedFile,
		GENERIC_READ,
		0,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL
	)) || INVALID_HANDLE_VALUE == hFile)
	{
		printf("Error at CreateFileA, code = %d\n", GetLastError());
		return FALSE;
	};

	LARGE_INTEGER u32FileSize;
	if (!GetFileSizeEx(
		hFile,
		&u32FileSize
	))
	{
		printf("Error at GetFileSizeEx, code = %d\n", GetLastError());
		return FALSE;
	};

	LPVOID lpPeContent;
	if (!(lpPeContent = VirtualAlloc(
		NULL,
		u32FileSize.QuadPart,
		(MEM_COMMIT | MEM_RESERVE),
		PAGE_READWRITE
	)))
	{
		printf("Error at VirtualAlloc, code = %d\n", GetLastError());
		return NULL;
	};

	DWORD dwReadBytes;
	if (!ReadFile(
		hFile,
		lpPeContent,
		u32FileSize.QuadPart,
		&dwReadBytes,
		NULL
	))
	{
		printf("Error at ReadFile, code = %d\n", GetLastError());
		return NULL;
	};

	CloseHandle(hFile);

	return lpPeContent;
}
// ZwUnmapViewOfSection syntax
typedef NTSTATUS(NTAPI* pZwUnmapViewOfSection)(
	HANDLE            ProcessHandle,
	PVOID             BaseAddress
	);
