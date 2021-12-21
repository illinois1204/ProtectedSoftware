#include <Windows.h>
#include <stdio.h>
#include "cast128.h"

bool __stdcall IsThunk(PVOID pThunk, bool* pfRel = NULL) {
#define CPU_JMP_MEM32   0x25FF
#define CPU_JMP_NEAR    0xE9

    bool fResult = false;
    if (pfRel)
        *pfRel = false;

    if (!IsBadReadPtr(pThunk, sizeof(WORD))) {
        if (*(WORD*)pThunk == CPU_JMP_MEM32) {
            PVOID** ppFunction = (PVOID**)((BYTE*)pThunk + sizeof(WORD));
            if (!IsBadReadPtr(*ppFunction, sizeof(DWORD)) && !IsBadReadPtr(**ppFunction, sizeof(DWORD))) {
                fResult = true;
            }
        }
        else {
            if (*LPBYTE(pThunk) == CPU_JMP_NEAR) {
                if (pfRel)
                    *pfRel = true;
                fResult = true;
            }
        }
    }
    return fResult;
}

PVOID __stdcall GetImportedFunctionAddress(PVOID pThunk) {
    PVOID pFunction = NULL;
    bool fRel;
    bool fThunk = IsThunk(pThunk, &fRel);

    for (; fThunk; fThunk = IsThunk(pThunk, &fRel)) {
        if (fRel)
            pThunk = LPBYTE(DWORD_PTR(pThunk) + 5 + *(DWORD*)(LPBYTE(pThunk) + 1));
        else {
            PVOID** ppFunction = (PVOID**)((BYTE*)pThunk + sizeof(WORD));
            pThunk = **ppFunction;
        }
    }
    return pThunk;
}

PVOID __stdcall GetFunctionAddress(PVOID pThunkOrRealAddr) {
    return IsThunk(pThunkOrRealAddr) ? GetImportedFunctionAddress(pThunkOrRealAddr) : pThunkOrRealAddr;
}

LPBYTE seek_label_in_function(PVOID protected_main, int label) {
    LPBYTE pCode = (LPBYTE)GetFunctionAddress(protected_main);
    const int FUNCTION_MAX_LENGTH = 256;
    for (int i = 0; i < FUNCTION_MAX_LENGTH; i++, pCode++) {
        if (*(DWORD*)pCode == label)
            break;
    }
    return pCode;
}

BOOL WriteProcessMemoryEx(PVOID pTo, PVOID pFrom, ULONG cb) {
    DWORD n = 0;
    BOOL f = WriteProcessMemory(HANDLE(-1), pTo, pFrom, cb, &n);
    if (f) {
        if (n != cb)
            return false;
        return true;
    }

    if (GetLastError() != ERROR_NOACCESS)
        return false;

    DWORD dwOldProtect;
    if (!VirtualProtect(pTo, cb, PAGE_WRITECOPY, &dwOldProtect))
        return false;

    f = WriteProcessMemory(HANDLE(-1), pTo, pFrom, cb, &n);
    VirtualProtect(pTo, cb, dwOldProtect, &dwOldProtect);

    if (f) {
        if (n != cb) {
            VirtualProtect(pTo, cb, dwOldProtect, &dwOldProtect);
            return false;
        }
    }
    return f;
}

int disable_jmp(LPBYTE protected_area_ptr) {
    //BOOL IsDbgPresent = FALSE;
    //CheckRemoteDebuggerPresent(GetCurrentProcess(), &IsDbgPresent);
    //if (IsDbgPresent) {
    //    printf("Debugger detected by CheckRemoteDebuggerPresent!\n");
    //    return -1;
    //}
    //if (IsDebuggerPresent()) {
    //    printf("Debuger detected by IsDbgPresent!\n");
    //    return -1;
    //}

    BYTE nop = 0x90;
    WriteProcessMemoryEx(protected_area_ptr - 3, &nop, sizeof(nop));
    WriteProcessMemoryEx(protected_area_ptr - 2, &nop, sizeof(nop));
    return 0;
}

void encrypt(LPBYTE start_of_function, int length) {
    CAST128 cast128;
    for (int i = 0; i < length; i += 2 * sizeof(DWORD)) {
        CAST128::Message Data = { *(DWORD*)(start_of_function + 4 + i), *(DWORD*)(start_of_function + 4 + i + sizeof(DWORD)) };
        cast128.encrypt(Data);
        WriteProcessMemoryEx(start_of_function + 4 + i, Data, sizeof(Data));
    }
}

void decrypt(LPBYTE start_of_function, int length) {
    CAST128 cast128;
    for (int i = 0; i < length; i += 2 * sizeof(DWORD)) {
        CAST128::Message Data = { *(DWORD*)(start_of_function + 4 + i), *(DWORD*)(start_of_function + 4 + i + sizeof(DWORD)) };
        cast128.decrypt(Data);
        WriteProcessMemoryEx(start_of_function + 4 + i, Data, sizeof(Data));
    }
}

int protected_main(int value) {
    const char* checking = "Checking entered value...\n";
    const char* success = "Success\n";
    _asm {
        jmp end
        mov eax, 0x11111111
        nop
    };

    int serial_key = 123;

    printf(checking);
    if (serial_key == value)
        printf(success);

    _asm {
        mov eax, 0x22222222
        end:
        nop
    };
    return 0;
}

int main()
{
    LPBYTE start_of_function = seek_label_in_function(&protected_main, 0x11111111);
    LPBYTE end_of_function = seek_label_in_function(&protected_main, 0x22222222);
    int length_of_function = end_of_function - start_of_function - 5;

    disable_jmp(start_of_function);
    //if (disable_jmp(start_of_function)) {
    //    system("pause");
    //    exit(-1);
    //}

    int value = 0;
    printf("Enter serial code: ");
    scanf_s("%d", &value);

    decrypt(start_of_function, length_of_function);
    protected_main(value);
    encrypt(start_of_function, length_of_function);

    return 0;
}