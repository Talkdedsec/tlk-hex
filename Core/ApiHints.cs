namespace tlk_hex.Core;

// Sik gorulen Windows API'leri icin parametre adlari.
// Bir import cagrisinin ustune prototip yorumu dusmek icin kullanilir.
public static class ApiHints
{
    // isim -> parametre adlari (sirayla)
    private static readonly Dictionary<string, string[]> Sigs = new(StringComparer.OrdinalIgnoreCase)
    {
        // --- dosya ---
        ["CreateFile"] = new[] { "lpFileName", "dwDesiredAccess", "dwShareMode", "lpSecurityAttributes", "dwCreationDisposition", "dwFlagsAndAttributes", "hTemplateFile" },
        ["ReadFile"] = new[] { "hFile", "lpBuffer", "nNumberOfBytesToRead", "lpNumberOfBytesRead", "lpOverlapped" },
        ["WriteFile"] = new[] { "hFile", "lpBuffer", "nNumberOfBytesToWrite", "lpNumberOfBytesWritten", "lpOverlapped" },
        ["DeleteFile"] = new[] { "lpFileName" },
        ["CopyFile"] = new[] { "lpExistingFileName", "lpNewFileName", "bFailIfExists" },
        ["MoveFile"] = new[] { "lpExistingFileName", "lpNewFileName" },
        ["SetFilePointer"] = new[] { "hFile", "lDistanceToMove", "lpDistanceToMoveHigh", "dwMoveMethod" },
        ["GetFileSize"] = new[] { "hFile", "lpFileSizeHigh" },
        ["FindFirstFile"] = new[] { "lpFileName", "lpFindFileData" },
        ["FindNextFile"] = new[] { "hFindFile", "lpFindFileData" },
        ["CreateDirectory"] = new[] { "lpPathName", "lpSecurityAttributes" },
        ["GetModuleFileName"] = new[] { "hModule", "lpFilename", "nSize" },
        ["GetTempPath"] = new[] { "nBufferLength", "lpBuffer" },

        // --- surec / is parcacigi ---
        ["CreateProcess"] = new[] { "lpApplicationName", "lpCommandLine", "lpProcessAttributes", "lpThreadAttributes", "bInheritHandles", "dwCreationFlags", "lpEnvironment", "lpCurrentDirectory", "lpStartupInfo", "lpProcessInformation" },
        ["ShellExecute"] = new[] { "hwnd", "lpOperation", "lpFile", "lpParameters", "lpDirectory", "nShowCmd" },
        ["WinExec"] = new[] { "lpCmdLine", "uCmdShow" },
        ["CreateThread"] = new[] { "lpThreadAttributes", "dwStackSize", "lpStartAddress", "lpParameter", "dwCreationFlags", "lpThreadId" },
        ["CreateRemoteThread"] = new[] { "hProcess", "lpThreadAttributes", "dwStackSize", "lpStartAddress", "lpParameter", "dwCreationFlags", "lpThreadId" },
        ["OpenProcess"] = new[] { "dwDesiredAccess", "bInheritHandle", "dwProcessId" },
        ["TerminateProcess"] = new[] { "hProcess", "uExitCode" },
        ["ExitProcess"] = new[] { "uExitCode" },
        ["WaitForSingleObject"] = new[] { "hHandle", "dwMilliseconds" },
        ["CreateToolhelp32Snapshot"] = new[] { "dwFlags", "th32ProcessID" },
        ["Process32First"] = new[] { "hSnapshot", "lppe" },
        ["Process32Next"] = new[] { "hSnapshot", "lppe" },

        // --- bellek / enjeksiyon ---
        ["VirtualAlloc"] = new[] { "lpAddress", "dwSize", "flAllocationType", "flProtect" },
        ["VirtualAllocEx"] = new[] { "hProcess", "lpAddress", "dwSize", "flAllocationType", "flProtect" },
        ["VirtualProtect"] = new[] { "lpAddress", "dwSize", "flNewProtect", "lpflOldProtect" },
        ["VirtualFree"] = new[] { "lpAddress", "dwSize", "dwFreeType" },
        ["WriteProcessMemory"] = new[] { "hProcess", "lpBaseAddress", "lpBuffer", "nSize", "lpNumberOfBytesWritten" },
        ["ReadProcessMemory"] = new[] { "hProcess", "lpBaseAddress", "lpBuffer", "nSize", "lpNumberOfBytesRead" },
        ["HeapAlloc"] = new[] { "hHeap", "dwFlags", "dwBytes" },
        ["GetProcAddress"] = new[] { "hModule", "lpProcName" },
        ["LoadLibrary"] = new[] { "lpLibFileName" },
        ["LoadLibraryEx"] = new[] { "lpLibFileName", "hFile", "dwFlags" },
        ["GetModuleHandle"] = new[] { "lpModuleName" },

        // --- registry ---
        ["RegOpenKeyEx"] = new[] { "hKey", "lpSubKey", "ulOptions", "samDesired", "phkResult" },
        ["RegCreateKeyEx"] = new[] { "hKey", "lpSubKey", "Reserved", "lpClass", "dwOptions", "samDesired", "lpSecurityAttributes", "phkResult", "lpdwDisposition" },
        ["RegSetValueEx"] = new[] { "hKey", "lpValueName", "Reserved", "dwType", "lpData", "cbData" },
        ["RegQueryValueEx"] = new[] { "hKey", "lpValueName", "lpReserved", "lpType", "lpData", "lpcbData" },
        ["RegDeleteKey"] = new[] { "hKey", "lpSubKey" },
        ["RegDeleteValue"] = new[] { "hKey", "lpValueName" },

        // --- ag ---
        ["socket"] = new[] { "af", "type", "protocol" },
        ["connect"] = new[] { "s", "name", "namelen" },
        ["send"] = new[] { "s", "buf", "len", "flags" },
        ["recv"] = new[] { "s", "buf", "len", "flags" },
        ["bind"] = new[] { "s", "addr", "namelen" },
        ["listen"] = new[] { "s", "backlog" },
        ["accept"] = new[] { "s", "addr", "addrlen" },
        ["WSAStartup"] = new[] { "wVersionRequested", "lpWSAData" },
        ["gethostbyname"] = new[] { "name" },
        ["getaddrinfo"] = new[] { "pNodeName", "pServiceName", "pHints", "ppResult" },
        ["InternetOpen"] = new[] { "lpszAgent", "dwAccessType", "lpszProxy", "lpszProxyBypass", "dwFlags" },
        ["InternetConnect"] = new[] { "hInternet", "lpszServerName", "nServerPort", "lpszUserName", "lpszPassword", "dwService", "dwFlags", "dwContext" },
        ["InternetOpenUrl"] = new[] { "hInternet", "lpszUrl", "lpszHeaders", "dwHeadersLength", "dwFlags", "dwContext" },
        ["InternetReadFile"] = new[] { "hFile", "lpBuffer", "dwNumberOfBytesToRead", "lpdwNumberOfBytesRead" },
        ["HttpOpenRequest"] = new[] { "hConnect", "lpszVerb", "lpszObjectName", "lpszVersion", "lpszReferrer", "lplpszAcceptTypes", "dwFlags", "dwContext" },
        ["HttpSendRequest"] = new[] { "hRequest", "lpszHeaders", "dwHeadersLength", "lpOptional", "dwOptionalLength" },
        ["URLDownloadToFile"] = new[] { "pCaller", "szURL", "szFileName", "dwReserved", "lpfnCB" },

        // --- kripto ---
        ["CryptAcquireContext"] = new[] { "phProv", "szContainer", "szProvider", "dwProvType", "dwFlags" },
        ["CryptEncrypt"] = new[] { "hKey", "hHash", "Final", "dwFlags", "pbData", "pdwDataLen", "dwBufLen" },
        ["CryptDecrypt"] = new[] { "hKey", "hHash", "Final", "dwFlags", "pbData", "pdwDataLen" },
        ["CryptGenKey"] = new[] { "hProv", "Algid", "dwFlags", "phKey" },
        ["CryptHashData"] = new[] { "hHash", "pbData", "dwDataLen", "dwFlags" },

        // --- girdi / izleme ---
        ["SetWindowsHookEx"] = new[] { "idHook", "lpfn", "hmod", "dwThreadId" },
        ["GetAsyncKeyState"] = new[] { "vKey" },
        ["GetKeyState"] = new[] { "nVirtKey" },
        ["RegisterHotKey"] = new[] { "hWnd", "id", "fsModifiers", "vk" },
        ["GetForegroundWindow"] = new string[0],
        ["GetClipboardData"] = new[] { "uFormat" },

        // --- kabuk / mesaj ---
        ["MessageBox"] = new[] { "hWnd", "lpText", "lpCaption", "uType" },
        ["wsprintf"] = new[] { "lpOut", "lpFmt", "..." },
        ["lstrcpy"] = new[] { "lpString1", "lpString2" },
        ["lstrcat"] = new[] { "lpString1", "lpString2" },
        ["lstrlen"] = new[] { "lpString" },

        // --- CRT ---
        ["memcpy"] = new[] { "dest", "src", "count" },
        ["memset"] = new[] { "dest", "value", "count" },
        ["strcmp"] = new[] { "str1", "str2" },
        ["strncmp"] = new[] { "str1", "str2", "count" },
        ["strcpy"] = new[] { "dest", "src" },
        ["strcat"] = new[] { "dest", "src" },
        ["strlen"] = new[] { "str" },
        ["malloc"] = new[] { "size" },
        ["free"] = new[] { "ptr" },
        ["fopen"] = new[] { "filename", "mode" },
        ["system"] = new[] { "command" },
        ["printf"] = new[] { "format", "..." },
        ["sprintf"] = new[] { "buffer", "format", "..." },

        // --- hata ayiklama karsiti ---
        ["IsDebuggerPresent"] = new string[0],
        ["CheckRemoteDebuggerPresent"] = new[] { "hProcess", "pbDebuggerPresent" },
        ["NtQueryInformationProcess"] = new[] { "ProcessHandle", "ProcessInformationClass", "ProcessInformation", "ProcessInformationLength", "ReturnLength" },
        ["OutputDebugString"] = new[] { "lpOutputString" },
        ["GetTickCount"] = new string[0],
    };

    private static string Strip(string name)
    {
        // __imp_, _ ve sondaki A/W/Ex varyantlarini normalize et
        if (name.StartsWith("__imp_")) name = name[6..];
        name = name.TrimStart('_');
        return name;
    }

    public static bool TryGet(string importName, out string prototype)
    {
        prototype = "";
        string n = Strip(importName);
        string[]? ps = null;
        if (Sigs.TryGetValue(n, out ps)) { }
        else if ((n.EndsWith("A") || n.EndsWith("W")) && Sigs.TryGetValue(n[..^1], out ps)) { }
        else if (n.EndsWith("Ex") && Sigs.TryGetValue(n[..^2], out ps)) { }
        else if (n.Length > 2 && (n[^1] is 'A' or 'W') && n.EndsWith("Ex" + n[^1])) { }
        if (ps == null) return false;
        prototype = n + "(" + string.Join(", ", ps) + ")";
        return true;
    }

    public static int Count => Sigs.Count;
}
