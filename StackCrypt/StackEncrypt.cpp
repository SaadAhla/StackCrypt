#include <Windows.h>
#include <stdio.h>
#include <winternl.h>
#include <intrin.h>
#include <tlhelp32.h>

#pragma comment(lib, "ntdll.lib")

typedef NTSTATUS(NTAPI* NtQueryInformationThreadPtr)(
    IN HANDLE ThreadHandle,
    IN THREADINFOCLASS ThreadInformationClass,
    OUT PVOID ThreadInformation,
    IN ULONG ThreadInformationLength,
    OUT PULONG ReturnLength OPTIONAL
    );


typedef struct _THREAD_BASIC_INFORMATION {
    NTSTATUS                ExitStatus;
    PVOID                   TebBaseAddress;
    CLIENT_ID               ClientId;
    KAFFINITY               AffinityMask;
    KPRIORITY               Priority;
    KPRIORITY               BasePriority;
} THREAD_BASIC_INFORMATION, * PTHREAD_BASIC_INFORMATION;


void xor_stack(void* stack_top, void* stack_base) {
    unsigned char* top = (unsigned char*)stack_top;
    unsigned char* base = (unsigned char*)stack_base;

    for (unsigned char* p = top; p < base; ++p) {
        *p ^= 0xAA;
    }
}

DWORD WINAPI EncryptDecryptThread(LPVOID lpParam) {
    DWORD currentThreadId = GetCurrentThreadId();
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);

    if (hSnapshot == INVALID_HANDLE_VALUE) {
        printf("Failed to create snapshot. Error: %lu\n", GetLastError());
        return 1;
    }

    THREADENTRY32 te32;
    te32.dwSize = sizeof(THREADENTRY32);

    if (Thread32First(hSnapshot, &te32)) {
        do {
            if (te32.th32OwnerProcessID == GetCurrentProcessId() && te32.th32ThreadID != currentThreadId) {
                HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, te32.th32ThreadID);

                if (hThread != NULL) {
                    SuspendThread(hThread);

                    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
                    NtQueryInformationThreadPtr NtQueryInformationThread = (NtQueryInformationThreadPtr)GetProcAddress(ntdll, "NtQueryInformationThread");

                    THREAD_BASIC_INFORMATION tbi;
                    NTSTATUS status = NtQueryInformationThread(hThread, (THREADINFOCLASS)0, &tbi, sizeof(tbi), NULL);

                    if (status == 0) {
                        PVOID teb_base_address = tbi.TebBaseAddress;
                        PNT_TIB tib = (PNT_TIB)malloc(sizeof(NT_TIB));
                        SIZE_T bytesRead;

                        if (ReadProcessMemory(GetCurrentProcess(), teb_base_address, tib, sizeof(NT_TIB), &bytesRead)) {
                            PVOID stack_top = tib->StackLimit;
                            PVOID stack_base = tib->StackBase;

                            xor_stack(stack_top, stack_base);
                        }
                        else {
                            printf("ReadProcessMemory (TEB) failed. Error: %lu\n", GetLastError());
                        }

                        free(tib);
                    }
                    else {
                        printf("NtQueryInformationThread failed with status: 0x%X\n", status);
                    }
                }
                else {
                    printf("Failed to open thread. Error: %lu\n", GetLastError());
                }
            }
        } while (Thread32Next(hSnapshot, &te32));
    }
    else {
        printf("Thread32First failed. Error:%lu\n", GetLastError());
    }

    Sleep(3000); // Sleep for 3 seconds

    // Decrypt the stacks and resume threads
    if (Thread32First(hSnapshot, &te32)) {
        do {
            if (te32.th32OwnerProcessID == GetCurrentProcessId() && te32.th32ThreadID != currentThreadId) {
                HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, te32.th32ThreadID);
                if (hThread != NULL) {
                    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
                    NtQueryInformationThreadPtr NtQueryInformationThread = (NtQueryInformationThreadPtr)GetProcAddress(ntdll, "NtQueryInformationThread");

                    THREAD_BASIC_INFORMATION tbi;
                    NTSTATUS status = NtQueryInformationThread(hThread, (THREADINFOCLASS)0, &tbi, sizeof(tbi), NULL);

                    if (status == 0) {
                        PVOID teb_base_address = tbi.TebBaseAddress;
                        PNT_TIB tib = (PNT_TIB)malloc(sizeof(NT_TIB));
                        SIZE_T bytesRead;

                        if (ReadProcessMemory(GetCurrentProcess(), teb_base_address, tib, sizeof(NT_TIB), &bytesRead)) {
                            PVOID stack_top = tib->StackLimit;
                            PVOID stack_base = tib->StackBase;

                            xor_stack(stack_top, stack_base);
                        }
                        else {
                            printf("ReadProcessMemory (TEB) failed. Error: %lu\n", GetLastError());
                        }

                        free(tib);
                    }
                    else {
                        printf("NtQueryInformationThread failed with status: 0x%X\n", status);
                    }

                    ResumeThread(hThread);
                    CloseHandle(hThread);
                }
                else {
                    printf("Failed to open thread. Error: %lu\n", GetLastError());
                }
            }
        } while (Thread32Next(hSnapshot, &te32));
    }
    else {
        printf("Thread32First failed. Error:%lu\n", GetLastError());
    }

    CloseHandle(hSnapshot);
    return 0;
}

int main() {
    while (true) {
        Sleep(3000);
        printf("[START Encrypting]\n");
        HANDLE hEncryptDecryptThread = CreateThread(NULL, 0, EncryptDecryptThread, NULL, 0, NULL);
        if (hEncryptDecryptThread == NULL) {
            printf("Failed to create encrypt/decrypt thread. Error: %lu\n", GetLastError());
            return 1;
        }

        WaitForSingleObject(hEncryptDecryptThread, INFINITE);
        CloseHandle(hEncryptDecryptThread);
        printf("[FINISH Encrypting]\n");
    }
    return 0;
}


