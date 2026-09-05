#include <Windows.h>
#include <bcrypt.h>
#include <intrin.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cwchar>
#include <string>
#include <vector>

namespace
{
    constexpr std::uintptr_t kKnownRegistrationRva = 0x30898D0;
    constexpr std::uintptr_t kKnownSwitchHandlerRva = 0x3298AB0;
    constexpr std::uintptr_t kKnownTaaWrapperRva = 0x308F1C0;
    constexpr std::uint32_t kKnownImageSize = 0x15D6C000;
    constexpr std::uint64_t kKnownFileSize = 361256856ULL;
    constexpr std::size_t kHookLength = 15;
    constexpr std::size_t kKnownActionOwnerOffset = 0x30;
    constexpr std::size_t kKnownGetRendererVtableOffset = 0x48;
    constexpr std::size_t kKnownSwitchHandlerVtableOffset = 0xA0;
    constexpr std::size_t kKnownSettingsPointerOffset = 0x590;
    constexpr std::size_t kKnownTemporalAaFlagOffset = 0x15E;
    constexpr std::size_t kKnownPostProcessSharpenFlagOffset = 0x166;
    constexpr std::uint8_t kKnownTaaActionId = 0x5A;

    constexpr char kTaaActionName[] =
        "PearlAbyssEngine.Debug.ToggleRenderingFeature.TemporalAA";
    constexpr char kSharpenActionName[] =
        "PearlAbyssEngine.Debug.ToggleRenderingFeature.PostProcessSharpen";
    constexpr char kTaaEnabledText[] = "Temporal AA is enabled";
    constexpr char kTaaDisabledText[] = "Temporal AA is disabled";
    constexpr char kSharpenEnabledText[] = "Post Process Sharpen is enabled";
    constexpr char kSharpenDisabledText[] = "Post Process Sharpen is disabled";

    constexpr std::array<std::uint8_t, 32> kKnownExeSha256 = {
        0xA9, 0x33, 0x36, 0xBC, 0x08, 0xF1, 0x61, 0x3B,
        0x60, 0x9F, 0x4F, 0x33, 0x1C, 0x68, 0x7B, 0x13,
        0xA8, 0xDB, 0x72, 0x9D, 0xD1, 0xAB, 0x99, 0xD8,
        0xFD, 0x09, 0xC9, 0xFB, 0xE0, 0x6B, 0xC2, 0x10
    };

    // These three complete instructions contain no relative operands, so the
    // 15 displaced bytes can be copied to the trampoline without relocation.
    constexpr std::array<std::uint8_t, kHookLength> kSafeRegistrationPrefix = {
        0x48, 0x89, 0x5C, 0x24, 0x08,
        0x48, 0x89, 0x74, 0x24, 0x10,
        0x48, 0x89, 0x7C, 0x24, 0x18
    };

    constexpr std::array<std::uint8_t, 33> kKnownTaaWrapperBytes = {
        0x48, 0x83, 0xEC, 0x28,
        0x48, 0x8B, 0x41, 0x38,
        0x48, 0x8B, 0x10,
        0x80, 0x7A, 0x49, 0x00,
        0x74, 0x1D,
        0x48, 0x8B, 0x49, 0x30,
        0x48, 0x8B, 0x01,
        0xFF, 0x50, 0x48,
        0xB2, 0x5A,
        0x48, 0x8B, 0xC8,
        0x4C
    };

    using RegistrationFunction = void(__fastcall*)(void*);
    using GetRendererFunction = void*(__fastcall*)(void*);

    enum class DisableResult
    {
        Pending,
        Success,
        Fatal
    };

    enum class RendererAccessMode
    {
        VirtualGetter,
        DirectOwnerPointer
    };

    struct ScanRange
    {
        const std::uint8_t* begin = nullptr;
        std::size_t size = 0;
        bool executable = false;
    };

    struct RuntimeProfile
    {
        bool adaptive = false;
        RendererAccessMode rendererAccessMode = RendererAccessMode::VirtualGetter;
        std::uintptr_t registrationAddress = 0;
        std::uintptr_t switchHandlerAddress = 0;
        std::uintptr_t taaWrapperAddress = 0;
        std::uintptr_t sharpenWrapperAddress = 0;
        std::size_t actionOwnerOffset = 0;
        std::size_t getRendererVtableOffset = 0;
        std::size_t rendererPointerOffset = 0;
        std::size_t switchHandlerVtableOffset = 0;
        std::size_t settingsPointerOffset = 0;
        std::size_t temporalAaFlagOffset = 0;
        std::size_t postProcessSharpenFlagOffset = 0;
        std::uint8_t taaActionId = 0;
        std::uint8_t sharpenActionId = 0;
    };

    struct ActionWrapperInfo
    {
        RendererAccessMode rendererAccessMode = RendererAccessMode::VirtualGetter;
        std::uintptr_t registrationAddress = 0;
        std::uintptr_t wrapperAddress = 0;
        std::size_t actionGateObjectOffset = 0;
        std::size_t actionGateFlagOffset = 0;
        std::size_t actionOwnerOffset = 0;
        std::size_t getRendererVtableOffset = 0;
        std::size_t rendererPointerOffset = 0;
        std::size_t switchHandlerVtableOffset = 0;
        std::uint8_t actionId = 0;
    };

    struct ToggleInfo
    {
        std::uintptr_t functionAddress = 0;
        std::uintptr_t blockAddress = 0;
        std::size_t settingsPointerOffset = 0;
        std::size_t flagOffset = 0;
    };

    struct ExecutableIdentity
    {
        std::uint64_t fileSize = 0;
        std::array<std::uint8_t, 32> sha256{};
    };

    HMODULE g_pluginModule = nullptr;
    std::uintptr_t g_imageBase = 0;
    std::uint32_t g_imageSize = 0;
    const RUNTIME_FUNCTION* g_runtimeFunctions = nullptr;
    std::size_t g_runtimeFunctionCount = 0;
    std::vector<ScanRange> g_scanRanges;
    RuntimeProfile g_profile{};
    RegistrationFunction g_originalRegistration = nullptr;
    void* g_trampoline = nullptr;
    std::atomic<void*> g_registrationContext{nullptr};
    std::atomic_bool g_taaAndSharpenDisabled{false};
    SRWLOCK g_logLock = SRWLOCK_INIT;
    std::wstring g_logPath;

    std::wstring GetModulePath(HMODULE module)
    {
        std::vector<wchar_t> buffer(32768);
        const DWORD length = GetModuleFileNameW(module, buffer.data(), static_cast<DWORD>(buffer.size()));
        if (length == 0 || length >= buffer.size()) {
            return {};
        }

        return std::wstring(buffer.data(), length);
    }

    bool IsCrimsonDesertHostProcess()
    {
        const std::wstring processPath = GetModulePath(nullptr);
        if (processPath.empty()) {
            return false;
        }

        const std::size_t separator = processPath.find_last_of(L"\\/");
        const wchar_t* fileName =
            separator == std::wstring::npos
                ? processPath.c_str()
                : processPath.c_str() + separator + 1;
        return _wcsicmp(fileName, L"CrimsonDesert.exe") == 0;
    }

    void InitializeLogPath()
    {
        g_logPath = GetModulePath(g_pluginModule);
        const std::size_t separator = g_logPath.find_last_of(L"\\/");
        if (separator == std::wstring::npos) {
            g_logPath = L"CrimsonDesertFTAA.log";
        }
        else {
            g_logPath.resize(separator + 1);
            g_logPath += L"CrimsonDesertFTAA.log";
        }
    }

    bool ResetLogForCurrentLaunch()
    {
        AcquireSRWLockExclusive(&g_logLock);
        const HANDLE file = CreateFileW(
            g_logPath.c_str(),
            GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr,
            CREATE_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            nullptr);
        const bool success = file != INVALID_HANDLE_VALUE;
        if (success) {
            CloseHandle(file);
        }
        ReleaseSRWLockExclusive(&g_logLock);
        return success;
    }

    void Log(const char* format, ...)
    {
        char message[2048]{};
        va_list arguments;
        va_start(arguments, format);
        vsnprintf_s(message, sizeof(message), _TRUNCATE, format, arguments);
        va_end(arguments);

        SYSTEMTIME time{};
        GetLocalTime(&time);

        char line[2304]{};
        sprintf_s(
            line,
            sizeof(line),
            "[%04u-%02u-%02u %02u:%02u:%02u.%03u] %s\r\n",
            time.wYear,
            time.wMonth,
            time.wDay,
            time.wHour,
            time.wMinute,
            time.wSecond,
            time.wMilliseconds,
            message);

        AcquireSRWLockExclusive(&g_logLock);
        const HANDLE file = CreateFileW(
            g_logPath.c_str(),
            FILE_APPEND_DATA,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr,
            OPEN_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            nullptr);

        if (file != INVALID_HANDLE_VALUE) {
            DWORD written = 0;
            WriteFile(file, line, static_cast<DWORD>(std::strlen(line)), &written, nullptr);
            CloseHandle(file);
        }
        ReleaseSRWLockExclusive(&g_logLock);
    }

    bool CalculateSha256(const std::wstring& path, std::array<std::uint8_t, 32>& output)
    {
        bool success = false;
        BCRYPT_ALG_HANDLE algorithm = nullptr;
        BCRYPT_HASH_HANDLE hash = nullptr;
        HANDLE file = INVALID_HANDLE_VALUE;
        std::vector<std::uint8_t> hashObject;

        DWORD objectSize = 0;
        DWORD hashSize = 0;
        DWORD resultSize = 0;

        if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) < 0) {
            goto cleanup;
        }
        if (BCryptGetProperty(
                algorithm,
                BCRYPT_OBJECT_LENGTH,
                reinterpret_cast<PUCHAR>(&objectSize),
                sizeof(objectSize),
                &resultSize,
                0) < 0) {
            goto cleanup;
        }
        if (BCryptGetProperty(
                algorithm,
                BCRYPT_HASH_LENGTH,
                reinterpret_cast<PUCHAR>(&hashSize),
                sizeof(hashSize),
                &resultSize,
                0) < 0 ||
            hashSize != output.size()) {
            goto cleanup;
        }

        hashObject.resize(objectSize);
        if (BCryptCreateHash(
                algorithm,
                &hash,
                hashObject.data(),
                static_cast<ULONG>(hashObject.size()),
                nullptr,
                0,
                0) < 0) {
            goto cleanup;
        }

        file = CreateFileW(
            path.c_str(),
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr,
            OPEN_EXISTING,
            FILE_FLAG_SEQUENTIAL_SCAN,
            nullptr);
        if (file == INVALID_HANDLE_VALUE) {
            goto cleanup;
        }

        {
            std::vector<std::uint8_t> buffer(1024 * 1024);
            for (;;) {
                DWORD bytesRead = 0;
                if (!ReadFile(file, buffer.data(), static_cast<DWORD>(buffer.size()), &bytesRead, nullptr)) {
                    goto cleanup;
                }
                if (bytesRead == 0) {
                    break;
                }
                if (BCryptHashData(hash, buffer.data(), bytesRead, 0) < 0) {
                    goto cleanup;
                }
            }
        }

        if (BCryptFinishHash(hash, output.data(), static_cast<ULONG>(output.size()), 0) < 0) {
            goto cleanup;
        }

        success = true;

    cleanup:
        if (file != INVALID_HANDLE_VALUE) {
            CloseHandle(file);
        }
        if (hash != nullptr) {
            BCryptDestroyHash(hash);
        }
        if (algorithm != nullptr) {
            BCryptCloseAlgorithmProvider(algorithm, 0);
        }
        return success;
    }

    std::string FormatSha256(const std::array<std::uint8_t, 32>& digest)
    {
        constexpr char digits[] = "0123456789ABCDEF";
        std::string result;
        result.resize(digest.size() * 2);
        for (std::size_t index = 0; index < digest.size(); ++index) {
            result[index * 2] = digits[digest[index] >> 4];
            result[index * 2 + 1] = digits[digest[index] & 0x0F];
        }
        return result;
    }

    bool IsReadable(const void* address, std::size_t size)
    {
        if (address == nullptr || size == 0) {
            return false;
        }

        MEMORY_BASIC_INFORMATION information{};
        if (VirtualQuery(address, &information, sizeof(information)) != sizeof(information)) {
            return false;
        }

        if (information.State != MEM_COMMIT ||
            (information.Protect & PAGE_GUARD) != 0 ||
            (information.Protect & PAGE_NOACCESS) != 0) {
            return false;
        }

        const auto begin = reinterpret_cast<std::uintptr_t>(address);
        const auto regionEnd = reinterpret_cast<std::uintptr_t>(information.BaseAddress) + information.RegionSize;
        return begin <= regionEnd && size <= regionEnd - begin;
    }

    bool IsRangeInsideMainImage(std::uintptr_t address, std::size_t size)
    {
        if (address < g_imageBase || size > g_imageSize) {
            return false;
        }
        return address - g_imageBase <= static_cast<std::uintptr_t>(g_imageSize - size);
    }

    bool IsInsideMainImage(const void* address)
    {
        return IsRangeInsideMainImage(reinterpret_cast<std::uintptr_t>(address), 1);
    }

    bool IsInsideExecutableRange(std::uintptr_t address, std::size_t size)
    {
        if (!IsRangeInsideMainImage(address, size)) {
            return false;
        }
        for (const ScanRange& range : g_scanRanges) {
            if (!range.executable) {
                continue;
            }
            const auto begin = reinterpret_cast<std::uintptr_t>(range.begin);
            if (address >= begin && address - begin <= range.size && size <= range.size - (address - begin)) {
                return true;
            }
        }
        return false;
    }

    bool ParseLoadedImage()
    {
        const auto* dosHeader = reinterpret_cast<const IMAGE_DOS_HEADER*>(g_imageBase);
        if (!IsReadable(dosHeader, sizeof(*dosHeader)) || dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
            Log("Main executable does not have a readable DOS header; plugin is inactive.");
            return false;
        }

        if (dosHeader->e_lfanew <= 0 || dosHeader->e_lfanew > 0x100000) {
            Log("Main executable has an implausible PE-header offset; plugin is inactive.");
            return false;
        }

        const auto* ntHeaders = reinterpret_cast<const IMAGE_NT_HEADERS64*>(g_imageBase + dosHeader->e_lfanew);
        if (!IsReadable(ntHeaders, sizeof(*ntHeaders)) ||
            ntHeaders->Signature != IMAGE_NT_SIGNATURE ||
            ntHeaders->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC ||
            ntHeaders->FileHeader.NumberOfSections == 0 ||
            ntHeaders->FileHeader.NumberOfSections > 96) {
            Log("Main executable does not have a valid PE32+ layout; plugin is inactive.");
            return false;
        }

        g_imageSize = ntHeaders->OptionalHeader.SizeOfImage;
        if (g_imageSize < 0x10000) {
            Log("Main executable image size is implausibly small; plugin is inactive.");
            return false;
        }

        const auto* section = IMAGE_FIRST_SECTION(ntHeaders);
        if (!IsReadable(section, sizeof(IMAGE_SECTION_HEADER) * ntHeaders->FileHeader.NumberOfSections)) {
            Log("Main executable section table is unreadable; plugin is inactive.");
            return false;
        }

        g_scanRanges.clear();
        for (WORD index = 0; index < ntHeaders->FileHeader.NumberOfSections; ++index) {
            const IMAGE_SECTION_HEADER& current = section[index];
            if (current.VirtualAddress >= g_imageSize) {
                continue;
            }

            std::size_t sectionSize = std::max<std::size_t>(
                current.Misc.VirtualSize,
                current.SizeOfRawData);
            sectionSize = std::min<std::size_t>(sectionSize, g_imageSize - current.VirtualAddress);
            if (sectionSize == 0) {
                continue;
            }

            const bool executable = (current.Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
            std::uintptr_t cursor = g_imageBase + current.VirtualAddress;
            const std::uintptr_t sectionEnd = cursor + sectionSize;
            while (cursor < sectionEnd) {
                MEMORY_BASIC_INFORMATION information{};
                if (VirtualQuery(
                        reinterpret_cast<const void*>(cursor),
                        &information,
                        sizeof(information)) != sizeof(information)) {
                    Log("VirtualQuery failed while mapping executable sections; plugin is inactive.");
                    return false;
                }

                const std::uintptr_t regionBegin = reinterpret_cast<std::uintptr_t>(information.BaseAddress);
                const std::uintptr_t regionEnd = regionBegin + information.RegionSize;
                const std::uintptr_t usableEnd = std::min(sectionEnd, regionEnd);
                if (usableEnd <= cursor) {
                    Log("Invalid memory region encountered while mapping executable sections.");
                    return false;
                }

                if (information.State == MEM_COMMIT &&
                    (information.Protect & PAGE_GUARD) == 0 &&
                    (information.Protect & PAGE_NOACCESS) == 0) {
                    g_scanRanges.push_back({
                        reinterpret_cast<const std::uint8_t*>(cursor),
                        static_cast<std::size_t>(usableEnd - cursor),
                        executable});
                }
                cursor = usableEnd;
            }
        }

        const IMAGE_DATA_DIRECTORY& exceptionDirectory =
            ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
        if (exceptionDirectory.VirtualAddress == 0 ||
            exceptionDirectory.Size < sizeof(RUNTIME_FUNCTION) ||
            exceptionDirectory.Size % sizeof(RUNTIME_FUNCTION) != 0 ||
            !IsRangeInsideMainImage(
                g_imageBase + exceptionDirectory.VirtualAddress,
                exceptionDirectory.Size)) {
            Log("Main executable has no valid x64 exception directory; adaptive scan is unavailable.");
            return false;
        }

        g_runtimeFunctions = reinterpret_cast<const RUNTIME_FUNCTION*>(
            g_imageBase + exceptionDirectory.VirtualAddress);
        g_runtimeFunctionCount = exceptionDirectory.Size / sizeof(RUNTIME_FUNCTION);
        if (!IsReadable(g_runtimeFunctions, exceptionDirectory.Size)) {
            Log("Main executable exception directory is unreadable; adaptive scan is unavailable.");
            return false;
        }

        return true;
    }

    bool ReadExecutableIdentity(ExecutableIdentity& identity)
    {
        const std::wstring executablePath = GetModulePath(nullptr);
        if (executablePath.empty()) {
            Log("Could not resolve the CrimsonDesert.exe path; plugin is inactive.");
            return false;
        }

        WIN32_FILE_ATTRIBUTE_DATA attributes{};
        if (!GetFileAttributesExW(executablePath.c_str(), GetFileExInfoStandard, &attributes)) {
            Log("Could not read CrimsonDesert.exe file attributes; plugin is inactive.");
            return false;
        }

        ULARGE_INTEGER size{};
        size.LowPart = attributes.nFileSizeLow;
        size.HighPart = attributes.nFileSizeHigh;
        identity.fileSize = size.QuadPart;

        if (!CalculateSha256(executablePath, identity.sha256)) {
            Log("Could not calculate the CrimsonDesert.exe SHA-256; plugin is inactive.");
            return false;
        }
        return true;
    }

    bool FindRuntimeFunction(
        std::uintptr_t address,
        std::uintptr_t& functionBegin,
        std::uintptr_t& functionEnd)
    {
        if (!IsRangeInsideMainImage(address, 1)) {
            return false;
        }
        const auto rva = static_cast<DWORD>(address - g_imageBase);
        for (std::size_t index = 0; index < g_runtimeFunctionCount; ++index) {
            const RUNTIME_FUNCTION& function = g_runtimeFunctions[index];
            if (rva >= function.BeginAddress && rva < function.EndAddress &&
                function.BeginAddress < function.EndAddress &&
                function.EndAddress <= g_imageSize) {
                functionBegin = g_imageBase + function.BeginAddress;
                functionEnd = g_imageBase + function.EndAddress;
                return true;
            }
        }
        return false;
    }

    bool FindUniqueAscii(const char* text, std::uintptr_t& address)
    {
        const std::size_t length = std::strlen(text) + 1;
        std::size_t matches = 0;
        address = 0;

        for (const ScanRange& range : g_scanRanges) {
            if (range.executable || range.size < length) {
                continue;
            }

            const std::uint8_t* cursor = range.begin;
            std::size_t remaining = range.size;
            while (remaining >= length) {
                const void* found = std::memchr(cursor, static_cast<unsigned char>(text[0]), remaining - length + 1);
                if (found == nullptr) {
                    break;
                }

                const auto* candidate = static_cast<const std::uint8_t*>(found);
                if (std::memcmp(candidate, text, length) == 0) {
                    ++matches;
                    address = reinterpret_cast<std::uintptr_t>(candidate);
                    if (matches > 1) {
                        return false;
                    }
                }

                const std::size_t consumed = static_cast<std::size_t>(candidate - cursor) + 1;
                cursor += consumed;
                remaining -= consumed;
            }
        }

        return matches == 1;
    }

    std::uintptr_t ResolveRipTarget(const std::uint8_t* instruction)
    {
        std::int32_t displacement = 0;
        std::memcpy(&displacement, instruction + 3, sizeof(displacement));
        return reinterpret_cast<std::uintptr_t>(instruction + 7) + displacement;
    }

    std::vector<std::uintptr_t> FindRipLeaReferences(
        std::uintptr_t target,
        int requiredRex,
        int requiredModRm)
    {
        std::vector<std::uintptr_t> references;
        for (const ScanRange& range : g_scanRanges) {
            if (!range.executable || range.size < 7) {
                continue;
            }

            for (std::size_t offset = 0; offset <= range.size - 7; ++offset) {
                const std::uint8_t* instruction = range.begin + offset;
                const bool isRipLea =
                    instruction[0] >= 0x48 && instruction[0] <= 0x4F &&
                    instruction[1] == 0x8D &&
                    (instruction[2] & 0xC7) == 0x05;
                if (!isRipLea ||
                    (requiredRex >= 0 && instruction[0] != requiredRex) ||
                    (requiredModRm >= 0 && instruction[2] != requiredModRm)) {
                    continue;
                }
                if (ResolveRipTarget(instruction) == target) {
                    references.push_back(reinterpret_cast<std::uintptr_t>(instruction));
                }
            }
        }
        return references;
    }

    bool ParseActionWrapper(const std::uint8_t* code, ActionWrapperInfo& info)
    {
        constexpr std::size_t legacyWrapperSize = 51;
        constexpr std::size_t compactWrapperSize = 34;
        const auto address = reinterpret_cast<std::uintptr_t>(code);
        if (!IsInsideExecutableRange(address, compactWrapperSize) ||
            !IsReadable(code, compactWrapperSize)) {
            return false;
        }

        RendererAccessMode accessMode = RendererAccessMode::VirtualGetter;
        std::size_t gateObjectOffset = 0;
        std::size_t gateFlagOffset = 0;
        std::size_t ownerOffset = 0;
        std::size_t getRendererOffset = 0;
        std::size_t rendererPointerOffset = 0;
        std::uint32_t switchOffset = 0;
        std::uint8_t actionId = 0;

        const bool legacyShape =
            IsInsideExecutableRange(address, legacyWrapperSize) &&
            IsReadable(code, legacyWrapperSize) &&
            std::memcmp(code, "\x48\x83\xEC\x28\x48\x8B\x41", 7) == 0 &&
            std::memcmp(code + 8, "\x48\x8B\x10\x80\x7A", 5) == 0 &&
            code[14] == 0x00 && code[15] == 0x74 && code[16] == 0x1D &&
            std::memcmp(code + 17, "\x48\x8B\x49", 3) == 0 &&
            std::memcmp(code + 21, "\x48\x8B\x01\xFF\x50", 5) == 0 &&
            code[27] == 0xB2 &&
            std::memcmp(
                code + 29,
                "\x48\x8B\xC8\x4C\x8B\x00\x48\x83\xC4\x28\x49\xFF\xA0",
                13) == 0 &&
            std::memcmp(code + 46, "\x48\x83\xC4\x28\xC3", 5) == 0;

        const bool compactShape =
            std::memcmp(code, "\x48\x8B\x41", 3) == 0 &&
            std::memcmp(code + 4, "\x48\x8B\x10\x80\x7A", 5) == 0 &&
            code[10] == 0x00 && code[11] == 0x74 && code[12] == 0x14 &&
            std::memcmp(code + 13, "\x48\x8B\x41", 3) == 0 &&
            code[17] == 0xB2 &&
            std::memcmp(code + 19, "\x48\x8B\x48", 3) == 0 &&
            std::memcmp(code + 23, "\x48\x8B\x01\x48\xFF\xA0", 6) == 0 &&
            code[33] == 0xC3;

        if (legacyShape) {
            gateObjectOffset = code[7];
            gateFlagOffset = code[13];
            ownerOffset = code[20];
            getRendererOffset = code[26];
            std::memcpy(&switchOffset, code + 42, sizeof(switchOffset));
            actionId = code[28];
        }
        else if (compactShape) {
            accessMode = RendererAccessMode::DirectOwnerPointer;
            gateObjectOffset = code[3];
            gateFlagOffset = code[9];
            ownerOffset = code[16];
            rendererPointerOffset = code[22];
            std::memcpy(&switchOffset, code + 29, sizeof(switchOffset));
            actionId = code[18];
        }
        else {
            return false;
        }

        if (gateObjectOffset == 0 || gateObjectOffset > 0x200 ||
            gateObjectOffset % sizeof(void*) != 0 ||
            gateFlagOffset == 0 || gateFlagOffset > 0x100 ||
            ownerOffset == 0 || ownerOffset > 0x200 || ownerOffset % sizeof(void*) != 0 ||
            switchOffset == 0 || switchOffset > 0x400 || switchOffset % sizeof(void*) != 0) {
            return false;
        }

        if (accessMode == RendererAccessMode::VirtualGetter) {
            if (getRendererOffset == 0 || getRendererOffset > 0x400 ||
                getRendererOffset % sizeof(void*) != 0) {
                return false;
            }
        }
        else if (rendererPointerOffset == 0 || rendererPointerOffset > 0x400 ||
                 rendererPointerOffset % sizeof(void*) != 0) {
            return false;
        }

        info.rendererAccessMode = accessMode;
        info.wrapperAddress = address;
        info.actionGateObjectOffset = gateObjectOffset;
        info.actionGateFlagOffset = gateFlagOffset;
        info.actionOwnerOffset = ownerOffset;
        info.getRendererVtableOffset = getRendererOffset;
        info.rendererPointerOffset = rendererPointerOffset;
        info.switchHandlerVtableOffset = switchOffset;
        info.actionId = actionId;
        return true;
    }

    bool ResolveActionWrapper(const char* actionName, const char* label, ActionWrapperInfo& result)
    {
        std::uintptr_t actionString = 0;
        if (!FindUniqueAscii(actionName, actionString)) {
            Log("Adaptive locator: %s action string was missing or non-unique.", label);
            return false;
        }

        const std::vector<std::uintptr_t> references =
            FindRipLeaReferences(actionString, 0x48, 0x15);
        std::vector<ActionWrapperInfo> candidates;

        for (const std::uintptr_t reference : references) {
            std::uintptr_t functionBegin = 0;
            std::uintptr_t functionEnd = 0;
            if (!FindRuntimeFunction(reference, functionBegin, functionEnd) ||
                functionEnd <= reference + 7) {
                continue;
            }

            const std::uintptr_t searchEnd = std::min(functionEnd, reference + 96);
            for (std::uintptr_t cursor = reference + 7; cursor + 7 <= searchEnd; ++cursor) {
                const auto* instruction = reinterpret_cast<const std::uint8_t*>(cursor);
                if (!IsReadable(instruction, 7) ||
                    instruction[0] != 0x48 || instruction[1] != 0x8D || instruction[2] != 0x0D) {
                    continue;
                }

                const std::uintptr_t wrapperAddress = ResolveRipTarget(instruction);
                ActionWrapperInfo candidate{};
                if (!ParseActionWrapper(
                        reinterpret_cast<const std::uint8_t*>(wrapperAddress),
                        candidate)) {
                    continue;
                }
                candidate.registrationAddress = functionBegin;

                const bool duplicate = std::any_of(
                    candidates.begin(),
                    candidates.end(),
                    [&](const ActionWrapperInfo& existing) {
                        return existing.wrapperAddress == candidate.wrapperAddress;
                    });
                if (!duplicate) {
                    candidates.push_back(candidate);
                }
            }
        }

        if (candidates.size() != 1) {
            Log(
                "Adaptive locator: %s registration wrapper produced %llu semantic candidates; expected one.",
                label,
                static_cast<unsigned long long>(candidates.size()));
            return false;
        }

        result = candidates.front();
        return true;
    }

    bool ParseToggleBlock(
        const std::uint8_t* code,
        std::uintptr_t enabledText,
        std::uintptr_t disabledText,
        ToggleInfo& info)
    {
        constexpr std::size_t blockSize = 71;
        const auto address = reinterpret_cast<std::uintptr_t>(code);
        if (!IsInsideExecutableRange(address, blockSize) || !IsReadable(code, blockSize)) {
            return false;
        }

        const bool immediateZeroCompare =
            std::memcmp(code + 7, "\x80\xB9", 2) == 0 && code[13] == 0x00;
        const bool registerCompare =
            std::memcmp(code + 7, "\x44\x38\x89", 3) == 0;

        if (std::memcmp(code, "\x48\x8B\x8B", 3) != 0 ||
            (!immediateZeroCompare && !registerCompare) ||
            std::memcmp(code + 14, "\x0F\x94\xC0\x88\x81", 5) != 0 ||
            std::memcmp(code + 23, "\x48\x8B\x83", 3) != 0 ||
            std::memcmp(code + 30, "\x0F\xB6\x88", 3) != 0 ||
            std::memcmp(code + 37, "\x48\x8D\x15", 3) != 0 ||
            std::memcmp(code + 44, "\x48\x8D\x05", 3) != 0 ||
            std::memcmp(code + 51, "\x84\xC9\x48\x0F\x45\xC2", 6) != 0 ||
            std::memcmp(code + 57, "\x4C\x8D\x05", 3) != 0 ||
            std::memcmp(code + 64, "\x48\x8D\x15", 3) != 0) {
            return false;
        }

        std::uint32_t settingsA = 0;
        std::uint32_t settingsB = 0;
        std::uint32_t flagA = 0;
        std::uint32_t flagB = 0;
        std::uint32_t flagC = 0;
        std::memcpy(&settingsA, code + 3, sizeof(settingsA));
        std::memcpy(&settingsB, code + 26, sizeof(settingsB));
        std::memcpy(
            &flagA,
            code + (immediateZeroCompare ? 9 : 10),
            sizeof(flagA));
        std::memcpy(&flagB, code + 19, sizeof(flagB));
        std::memcpy(&flagC, code + 33, sizeof(flagC));

        if (settingsA != settingsB || flagA != flagB || flagA != flagC ||
            settingsA < sizeof(void*) || settingsA > 0x4000 || settingsA % sizeof(void*) != 0 ||
            flagA == 0 || flagA > 0x4000 ||
            ResolveRipTarget(code + 57) != enabledText ||
            ResolveRipTarget(code + 64) != disabledText) {
            return false;
        }

        info.blockAddress = address;
        info.settingsPointerOffset = settingsA;
        info.flagOffset = flagA;
        return true;
    }

    bool ResolveToggle(
        const char* enabledText,
        const char* disabledText,
        const char* label,
        ToggleInfo& result)
    {
        std::uintptr_t enabledAddress = 0;
        std::uintptr_t disabledAddress = 0;
        if (!FindUniqueAscii(enabledText, enabledAddress) ||
            !FindUniqueAscii(disabledText, disabledAddress)) {
            Log("Adaptive locator: %s status strings were missing or non-unique.", label);
            return false;
        }

        const std::vector<std::uintptr_t> enabledReferences =
            FindRipLeaReferences(enabledAddress, -1, -1);
        std::vector<std::uintptr_t> functions;
        for (const std::uintptr_t reference : enabledReferences) {
            std::uintptr_t functionBegin = 0;
            std::uintptr_t functionEnd = 0;
            if (!FindRuntimeFunction(reference, functionBegin, functionEnd) ||
                functionEnd <= functionBegin || functionEnd - functionBegin > 0x10000) {
                continue;
            }
            if (std::find(functions.begin(), functions.end(), functionBegin) == functions.end()) {
                functions.push_back(functionBegin);
            }
        }

        std::vector<ToggleInfo> candidates;
        for (const std::uintptr_t functionBegin : functions) {
            std::uintptr_t ignoredBegin = 0;
            std::uintptr_t functionEnd = 0;
            if (!FindRuntimeFunction(functionBegin, ignoredBegin, functionEnd)) {
                continue;
            }

            for (std::uintptr_t cursor = functionBegin; cursor + 71 <= functionEnd; ++cursor) {
                ToggleInfo candidate{};
                if (!ParseToggleBlock(
                        reinterpret_cast<const std::uint8_t*>(cursor),
                        enabledAddress,
                        disabledAddress,
                        candidate)) {
                    continue;
                }
                candidate.functionAddress = functionBegin;
                candidates.push_back(candidate);
            }
        }

        if (candidates.size() != 1) {
            Log(
                "Adaptive locator: %s switch branch produced %llu semantic candidates; expected one.",
                label,
                static_cast<unsigned long long>(candidates.size()));
            return false;
        }

        result = candidates.front();
        return true;
    }

    bool ResolveAdaptiveProfile(RuntimeProfile& profile)
    {
        ActionWrapperInfo taaAction{};
        ActionWrapperInfo sharpenAction{};
        if (!ResolveActionWrapper(kTaaActionName, "TemporalAA", taaAction) ||
            !ResolveActionWrapper(kSharpenActionName, "PostProcessSharpen", sharpenAction)) {
            return false;
        }

        if (taaAction.registrationAddress != sharpenAction.registrationAddress ||
            taaAction.wrapperAddress == sharpenAction.wrapperAddress ||
            taaAction.rendererAccessMode != sharpenAction.rendererAccessMode ||
            taaAction.actionGateObjectOffset != sharpenAction.actionGateObjectOffset ||
            taaAction.actionGateFlagOffset != sharpenAction.actionGateFlagOffset ||
            taaAction.actionOwnerOffset != sharpenAction.actionOwnerOffset ||
            taaAction.getRendererVtableOffset != sharpenAction.getRendererVtableOffset ||
            taaAction.rendererPointerOffset != sharpenAction.rendererPointerOffset ||
            taaAction.switchHandlerVtableOffset != sharpenAction.switchHandlerVtableOffset ||
            taaAction.actionId == sharpenAction.actionId) {
            Log("Adaptive locator: the TAA and sharpening callback paths did not agree.");
            return false;
        }

        const auto* registration = reinterpret_cast<const std::uint8_t*>(taaAction.registrationAddress);
        if (!IsInsideExecutableRange(taaAction.registrationAddress, kHookLength) ||
            !IsReadable(registration, kHookLength) ||
            std::memcmp(
                registration,
                kSafeRegistrationPrefix.data(),
                kSafeRegistrationPrefix.size()) != 0) {
            Log("Adaptive locator: registration entry does not have the relocatable 15-byte hook prefix.");
            return false;
        }

        ToggleInfo taaToggle{};
        ToggleInfo sharpenToggle{};
        if (!ResolveToggle(kTaaEnabledText, kTaaDisabledText, "TemporalAA", taaToggle) ||
            !ResolveToggle(
                kSharpenEnabledText,
                kSharpenDisabledText,
                "PostProcessSharpen",
                sharpenToggle)) {
            return false;
        }

        const std::size_t flagDistance =
            taaToggle.flagOffset > sharpenToggle.flagOffset
                ? taaToggle.flagOffset - sharpenToggle.flagOffset
                : sharpenToggle.flagOffset - taaToggle.flagOffset;
        if (taaToggle.functionAddress != sharpenToggle.functionAddress ||
            taaToggle.settingsPointerOffset != sharpenToggle.settingsPointerOffset ||
            taaToggle.flagOffset == sharpenToggle.flagOffset ||
            flagDistance > 0x100) {
            Log("Adaptive locator: the TAA and sharpening native switch branches did not agree.");
            return false;
        }

        profile.adaptive = true;
        profile.rendererAccessMode = taaAction.rendererAccessMode;
        profile.registrationAddress = taaAction.registrationAddress;
        profile.switchHandlerAddress = taaToggle.functionAddress;
        profile.taaWrapperAddress = taaAction.wrapperAddress;
        profile.sharpenWrapperAddress = sharpenAction.wrapperAddress;
        profile.actionOwnerOffset = taaAction.actionOwnerOffset;
        profile.getRendererVtableOffset = taaAction.getRendererVtableOffset;
        profile.rendererPointerOffset = taaAction.rendererPointerOffset;
        profile.switchHandlerVtableOffset = taaAction.switchHandlerVtableOffset;
        profile.settingsPointerOffset = taaToggle.settingsPointerOffset;
        profile.temporalAaFlagOffset = taaToggle.flagOffset;
        profile.postProcessSharpenFlagOffset = sharpenToggle.flagOffset;
        profile.taaActionId = taaAction.actionId;
        profile.sharpenActionId = sharpenAction.actionId;
        return true;
    }

    RuntimeProfile MakeKnownProfile()
    {
        RuntimeProfile profile{};
        profile.registrationAddress = g_imageBase + kKnownRegistrationRva;
        profile.switchHandlerAddress = g_imageBase + kKnownSwitchHandlerRva;
        profile.taaWrapperAddress = g_imageBase + kKnownTaaWrapperRva;
        profile.actionOwnerOffset = kKnownActionOwnerOffset;
        profile.getRendererVtableOffset = kKnownGetRendererVtableOffset;
        profile.switchHandlerVtableOffset = kKnownSwitchHandlerVtableOffset;
        profile.settingsPointerOffset = kKnownSettingsPointerOffset;
        profile.temporalAaFlagOffset = kKnownTemporalAaFlagOffset;
        profile.postProcessSharpenFlagOffset = kKnownPostProcessSharpenFlagOffset;
        profile.taaActionId = kKnownTaaActionId;
        return profile;
    }

    bool VerifyKnownCode()
    {
        const auto* registration = reinterpret_cast<const void*>(g_imageBase + kKnownRegistrationRva);
        const auto* wrapper = reinterpret_cast<const void*>(g_imageBase + kKnownTaaWrapperRva);
        if (!IsReadable(registration, kSafeRegistrationPrefix.size()) ||
            std::memcmp(
                registration,
                kSafeRegistrationPrefix.data(),
                kSafeRegistrationPrefix.size()) != 0) {
            Log("Known-build registration signature mismatch; refusing to install hook.");
            return false;
        }
        if (!IsReadable(wrapper, kKnownTaaWrapperBytes.size()) ||
            std::memcmp(wrapper, kKnownTaaWrapperBytes.data(), kKnownTaaWrapperBytes.size()) != 0) {
            Log("Known-build native TAA callback signature mismatch; refusing to install hook.");
            return false;
        }
        return true;
    }

    bool AdaptiveProfileMatchesKnown(const RuntimeProfile& adaptive)
    {
        return adaptive.rendererAccessMode == RendererAccessMode::VirtualGetter &&
            adaptive.registrationAddress == g_imageBase + kKnownRegistrationRva &&
            adaptive.switchHandlerAddress == g_imageBase + kKnownSwitchHandlerRva &&
            adaptive.taaWrapperAddress == g_imageBase + kKnownTaaWrapperRva &&
            adaptive.actionOwnerOffset == kKnownActionOwnerOffset &&
            adaptive.getRendererVtableOffset == kKnownGetRendererVtableOffset &&
            adaptive.rendererPointerOffset == 0 &&
            adaptive.switchHandlerVtableOffset == kKnownSwitchHandlerVtableOffset &&
            adaptive.settingsPointerOffset == kKnownSettingsPointerOffset &&
            adaptive.temporalAaFlagOffset == kKnownTemporalAaFlagOffset &&
            adaptive.postProcessSharpenFlagOffset == kKnownPostProcessSharpenFlagOffset &&
            adaptive.taaActionId == kKnownTaaActionId;
    }

    void LogProfile(const RuntimeProfile& profile, const char* label)
    {
        const bool directRenderer =
            profile.rendererAccessMode == RendererAccessMode::DirectOwnerPointer;
        const std::size_t rendererAccessOffset =
            directRenderer ? profile.rendererPointerOffset : profile.getRendererVtableOffset;
        Log(
            "%s profile: registration RVA 0x%llX, switch RVA 0x%llX, owner +0x%llX, "
            "renderer %s +0x%llX, switch slot +0x%llX, settings +0x%llX, "
            "flags +0x%llX/+0x%llX, "
            "action IDs 0x%02X/0x%02X.",
            label,
            static_cast<unsigned long long>(profile.registrationAddress - g_imageBase),
            static_cast<unsigned long long>(profile.switchHandlerAddress - g_imageBase),
            static_cast<unsigned long long>(profile.actionOwnerOffset),
            directRenderer ? "owner pointer" : "virtual getter slot",
            static_cast<unsigned long long>(rendererAccessOffset),
            static_cast<unsigned long long>(profile.switchHandlerVtableOffset),
            static_cast<unsigned long long>(profile.settingsPointerOffset),
            static_cast<unsigned long long>(profile.temporalAaFlagOffset),
            static_cast<unsigned long long>(profile.postProcessSharpenFlagOffset),
            profile.taaActionId,
            profile.sharpenActionId);
    }

    bool SelectRuntimeProfile()
    {
        ExecutableIdentity identity{};
        if (!ReadExecutableIdentity(identity)) {
            return false;
        }

        const std::string digest = FormatSha256(identity.sha256);
        const bool knownBuild =
            identity.fileSize == kKnownFileSize &&
            g_imageSize == kKnownImageSize &&
            identity.sha256 == kKnownExeSha256;

        if (knownBuild) {
            if (!VerifyKnownCode()) {
                Log("Exact executable identity matched, but loaded code did not; plugin is inactive.");
                return false;
            }

            g_profile = MakeKnownProfile();
            Log("Exact CrimsonDesert.exe build verified (1.0.0.2692).");

            RuntimeProfile adaptive{};
            if (ResolveAdaptiveProfile(adaptive)) {
                if (AdaptiveProfileMatchesKnown(adaptive)) {
                    Log("Adaptive locator self-test matched every known renderer landmark.");
                    LogProfile(adaptive, "Adaptive self-test");
                }
                else {
                    Log(
                        "Adaptive locator self-test disagreed with the verified profile; "
                        "the exact known profile remains active.");
                }
            }
            else {
                Log(
                    "Adaptive locator self-test did not resolve; the exact known profile remains active.");
            }
            return true;
        }

        Log(
            "Unrecognized CrimsonDesert.exe: file size %llu, image size 0x%X, SHA-256 %s.",
            static_cast<unsigned long long>(identity.fileSize),
            g_imageSize,
            digest.c_str());
        Log("Attempting the read-only, fail-closed adaptive locator.");

        RuntimeProfile adaptive{};
        if (!ResolveAdaptiveProfile(adaptive)) {
            Log("Adaptive locator failed; plugin is inactive and made no memory changes.");
            return false;
        }

        g_profile = adaptive;
        Log("Adaptive locator resolved one internally consistent renderer path.");
        LogProfile(g_profile, "Adaptive");
        return true;
    }

    void WriteAbsoluteJump(std::uint8_t* destination, const void* target)
    {
        destination[0] = 0xFF;
        destination[1] = 0x25;
        destination[2] = 0x00;
        destination[3] = 0x00;
        destination[4] = 0x00;
        destination[5] = 0x00;
        const auto targetValue = reinterpret_cast<std::uintptr_t>(target);
        std::memcpy(destination + 6, &targetValue, sizeof(targetValue));
    }

    DisableResult TryDisableTemporalAaAndSharpen(void* registrationContext)
    {
        if (registrationContext == nullptr ||
            !IsReadable(registrationContext, g_profile.actionOwnerOffset + sizeof(void*))) {
            return DisableResult::Pending;
        }

        __try {
            void* actionOwner = *reinterpret_cast<void**>(
                reinterpret_cast<std::uint8_t*>(registrationContext) + g_profile.actionOwnerOffset);
            if (actionOwner == nullptr) {
                return DisableResult::Pending;
            }
            if (!IsReadable(actionOwner, sizeof(void*))) {
                Log(
                    "Engine owner at callback context +0x%llX is not readable.",
                    static_cast<unsigned long long>(g_profile.actionOwnerOffset));
                return DisableResult::Fatal;
            }

            void* renderer = nullptr;
            if (g_profile.rendererAccessMode == RendererAccessMode::VirtualGetter) {
                auto** ownerVtable = *reinterpret_cast<void***>(actionOwner);
                if (!IsReadable(ownerVtable, g_profile.getRendererVtableOffset + sizeof(void*))) {
                    Log("Engine-owner vtable is not readable.");
                    return DisableResult::Fatal;
                }

                const auto getRenderer = reinterpret_cast<GetRendererFunction>(
                    ownerVtable[g_profile.getRendererVtableOffset / sizeof(void*)]);
                if (!IsInsideMainImage(reinterpret_cast<const void*>(getRenderer))) {
                    Log(
                        "Renderer getter is outside the main executable; "
                        "refusing both renderer writes.");
                    return DisableResult::Fatal;
                }

                renderer = getRenderer(actionOwner);
            }
            else {
                if (!IsReadable(
                        actionOwner,
                        g_profile.rendererPointerOffset + sizeof(void*))) {
                    Log("Engine owner does not expose a readable verified renderer pointer.");
                    return DisableResult::Fatal;
                }
                renderer = *reinterpret_cast<void**>(
                    reinterpret_cast<std::uint8_t*>(actionOwner) +
                    g_profile.rendererPointerOffset);
            }

            if (renderer == nullptr) {
                return DisableResult::Pending;
            }
            if (!IsReadable(renderer, g_profile.settingsPointerOffset + sizeof(void*))) {
                Log(
                    "Renderer pointer %p became non-null but is unreadable (engine owner %p).",
                    renderer,
                    actionOwner);
                return DisableResult::Fatal;
            }

            auto** rendererVtable = *reinterpret_cast<void***>(renderer);
            if (!IsReadable(rendererVtable, g_profile.switchHandlerVtableOffset + sizeof(void*))) {
                Log("Renderer vtable is not readable.");
                return DisableResult::Fatal;
            }

            const auto nativeSwitch = reinterpret_cast<const void*>(
                rendererVtable[g_profile.switchHandlerVtableOffset / sizeof(void*)]);
            if (nativeSwitch != reinterpret_cast<const void*>(g_profile.switchHandlerAddress)) {
                Log(
                    "Renderer switch slot did not point to the verified native handler RVA 0x%llX; "
                    "refusing both renderer writes.",
                    static_cast<unsigned long long>(g_profile.switchHandlerAddress - g_imageBase));
                return DisableResult::Fatal;
            }

            void* settings = *reinterpret_cast<void**>(
                reinterpret_cast<std::uint8_t*>(renderer) + g_profile.settingsPointerOffset);
            if (settings == nullptr) {
                return DisableResult::Pending;
            }

            const std::size_t lastFlagOffset = std::max(
                g_profile.temporalAaFlagOffset,
                g_profile.postProcessSharpenFlagOffset);
            if (!IsReadable(settings, lastFlagOffset + sizeof(std::uint8_t))) {
                Log("Renderer settings pointer became non-null but is unreadable.");
                return DisableResult::Fatal;
            }

            auto* temporalAaEnabled = reinterpret_cast<std::uint8_t*>(
                reinterpret_cast<std::uint8_t*>(settings) + g_profile.temporalAaFlagOffset);
            auto* postProcessSharpenEnabled = reinterpret_cast<std::uint8_t*>(
                reinterpret_cast<std::uint8_t*>(settings) + g_profile.postProcessSharpenFlagOffset);

            const std::uint8_t taaBefore = *temporalAaEnabled;
            const std::uint8_t sharpenBefore = *postProcessSharpenEnabled;
            if (taaBefore > 1) {
                Log("Native TAA flag had unexpected value %u; refusing both renderer writes.", taaBefore);
                return DisableResult::Fatal;
            }
            if (sharpenBefore > 1) {
                Log(
                    "Post-process sharpen flag had unexpected value %u; refusing both renderer writes.",
                    sharpenBefore);
                return DisableResult::Fatal;
            }

            Log(
                "Renderer and settings are live; native TAA=%u at +0x%llX, "
                "post-process sharpen=%u at +0x%llX.",
                taaBefore,
                static_cast<unsigned long long>(g_profile.temporalAaFlagOffset),
                sharpenBefore,
                static_cast<unsigned long long>(g_profile.postProcessSharpenFlagOffset));

            if (taaBefore != 0) {
                _InterlockedExchange8(reinterpret_cast<volatile char*>(temporalAaEnabled), 0);
            }
            if (sharpenBefore != 0) {
                _InterlockedExchange8(reinterpret_cast<volatile char*>(postProcessSharpenEnabled), 0);
            }

            const std::uint8_t taaAfter = *temporalAaEnabled;
            const std::uint8_t sharpenAfter = *postProcessSharpenEnabled;
            if (taaAfter != 0 || sharpenAfter != 0) {
                Log(
                    "The atomic renderer writes completed, but native TAA=%u and post-process sharpen=%u.",
                    taaAfter,
                    sharpenAfter);
                return DisableResult::Fatal;
            }

            Log(
                "Success: native TAA and post-process sharpening are disabled "
                "(one-time atomic settings writes; no recurring patch loop).");
            g_taaAndSharpenDisabled.store(true, std::memory_order_release);
            return DisableResult::Success;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            Log(
                "A structured exception occurred while resolving the native renderer path; "
                "polling has stopped.");
            return DisableResult::Fatal;
        }
    }

    void __fastcall RegistrationDetour(void* self)
    {
        g_originalRegistration(self);

        void* expected = nullptr;
        if (g_registrationContext.compare_exchange_strong(
                expected,
                self,
                std::memory_order_release,
                std::memory_order_relaxed)) {
            Log("Captured the debug-action callback context; waiting for engine initialization.");
        }
    }

    bool InstallRegistrationHook()
    {
        auto* target = reinterpret_cast<std::uint8_t*>(g_profile.registrationAddress);
        if (!IsInsideExecutableRange(g_profile.registrationAddress, kHookLength) ||
            !IsReadable(target, kHookLength) ||
            std::memcmp(target, kSafeRegistrationPrefix.data(), kSafeRegistrationPrefix.size()) != 0) {
            Log("Registration hook target changed after validation; plugin is inactive.");
            return false;
        }

        constexpr std::size_t jumpSize = 14;
        constexpr std::size_t trampolineSize = kHookLength + jumpSize;
        auto* trampoline = static_cast<std::uint8_t*>(VirtualAlloc(
            nullptr,
            trampolineSize,
            MEM_RESERVE | MEM_COMMIT,
            PAGE_EXECUTE_READWRITE));
        if (trampoline == nullptr) {
            Log("VirtualAlloc for the registration trampoline failed with error %lu.", GetLastError());
            return false;
        }

        std::memcpy(trampoline, target, kHookLength);
        WriteAbsoluteJump(trampoline + kHookLength, target + kHookLength);
        FlushInstructionCache(GetCurrentProcess(), trampoline, trampolineSize);

        std::array<std::uint8_t, kHookLength> patch{};
        patch.fill(0x90);
        WriteAbsoluteJump(patch.data(), reinterpret_cast<const void*>(&RegistrationDetour));

        DWORD oldProtection = 0;
        if (!VirtualProtect(target, kHookLength, PAGE_EXECUTE_READWRITE, &oldProtection)) {
            Log("VirtualProtect for the registration hook failed with error %lu.", GetLastError());
            VirtualFree(trampoline, 0, MEM_RELEASE);
            return false;
        }

        g_trampoline = trampoline;
        g_originalRegistration = reinterpret_cast<RegistrationFunction>(trampoline);
        std::memcpy(target, patch.data(), patch.size());
        FlushInstructionCache(GetCurrentProcess(), target, patch.size());

        DWORD ignoredProtection = 0;
        VirtualProtect(target, kHookLength, oldProtection, &ignoredProtection);
        Log(
            "%s debug-action registration hook installed; waiting to capture its callback context.",
            g_profile.adaptive ? "Adaptive" : "Known-profile");
        return true;
    }

    DWORD WINAPI InitializePlugin(void*)
    {
        // Ultimate ASI Loader can be inherited by launchers or helper programs
        // in the same installation. Ignore them completely so they cannot
        // scan the wrong image or truncate the real game's diagnostic log.
        if (!IsCrimsonDesertHostProcess()) {
            return 0;
        }

        InitializeLogPath();
        const bool logWasReset = ResetLogForCurrentLaunch();
        Log("CrimsonDesertFTAA 0.2.2 adaptive test loaded.");
        if (!logWasReset) {
            Log("Warning: the log could not be truncated at launch; new messages are being appended.");
        }

        g_imageBase = reinterpret_cast<std::uintptr_t>(GetModuleHandleW(nullptr));
        if (g_imageBase == 0) {
            Log("Could not resolve the main module; plugin is inactive.");
            return 0;
        }

        if (!ParseLoadedImage() || !SelectRuntimeProfile()) {
            Log("Build/profile verification failed; plugin is inactive.");
            return 0;
        }

        if (!InstallRegistrationHook()) {
            Log("Hook installation failed; plugin is inactive.");
            return 0;
        }

        constexpr DWORD pollIntervalMilliseconds = 250;
        constexpr DWORD maximumAttempts = (10 * 60 * 1000) / pollIntervalMilliseconds;
        for (DWORD attempt = 0; attempt < maximumAttempts; ++attempt) {
            void* context = g_registrationContext.load(std::memory_order_acquire);
            if (context != nullptr) {
                const DisableResult result = TryDisableTemporalAaAndSharpen(context);
                if (result == DisableResult::Success || result == DisableResult::Fatal) {
                    return 0;
                }
            }

            Sleep(pollIntervalMilliseconds);
        }

        Log(
            "Timed out after ten minutes without finding live renderer settings; "
            "no TAA or sharpening write was made.");
        return 0;
    }
}

BOOL APIENTRY DllMain(HMODULE module, DWORD reason, LPVOID)
{
    if (reason == DLL_PROCESS_ATTACH) {
        g_pluginModule = module;
        DisableThreadLibraryCalls(module);
        const HANDLE thread = CreateThread(nullptr, 0, InitializePlugin, nullptr, 0, nullptr);
        if (thread != nullptr) {
            CloseHandle(thread);
        }
    }

    return TRUE;
}
