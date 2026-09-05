// Reuse the reviewed 0.2.2 runtime locator and write path without modifying
// that historical source file. The three entrypoint names are isolated so this
// translation unit can add the 0.4.0 companion-profile authorization layer.
#define SelectRuntimeProfile SelectRuntimeProfileV022
#define InitializePlugin InitializePluginV022
#define DllMain DllMainV022
#include "../src/CrimsonDesertTAA.cpp"
#undef DllMain
#undef InitializePlugin
#undef SelectRuntimeProfile

#include "../src/CompanionContract.h"

#include <climits>

// The updater parses this exported data record directly from the ASI's PE
// image. It never loads or executes the ASI merely to test compatibility.
extern "C"
{
    ftaa::CompanionContractV1
        CrimsonDesertFTAACompanionContract = ftaa::kCompanionContractV1;
}

namespace
{
    enum class CompanionProfileResult
    {
        Missing,
        DifferentExecutable,
        Invalid,
        Valid
    };

    std::wstring GetCompanionSiblingPath(const wchar_t* fileName)
    {
        std::wstring path = GetModulePath(g_pluginModule);
        const std::size_t separator = path.find_last_of(L"\\/");
        if (separator == std::wstring::npos) {
            return fileName;
        }
        path.resize(separator + 1);
        path += fileName;
        return path;
    }

    bool CalculateCompanionBufferSha256(
        const std::uint8_t* data,
        std::size_t size,
        std::array<std::uint8_t, 32>& output)
    {
        if (data == nullptr || size > static_cast<std::size_t>(ULONG_MAX)) {
            return false;
        }

        BCRYPT_ALG_HANDLE algorithm = nullptr;
        BCRYPT_HASH_HANDLE hash = nullptr;
        std::vector<std::uint8_t> hashObject;
        bool success = false;
        DWORD objectSize = 0;
        DWORD hashSize = 0;
        DWORD returned = 0;

        if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) < 0 ||
            BCryptGetProperty(
                algorithm,
                BCRYPT_OBJECT_LENGTH,
                reinterpret_cast<PUCHAR>(&objectSize),
                sizeof(objectSize),
                &returned,
                0) < 0 ||
            BCryptGetProperty(
                algorithm,
                BCRYPT_HASH_LENGTH,
                reinterpret_cast<PUCHAR>(&hashSize),
                sizeof(hashSize),
                &returned,
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
                0) < 0 ||
            BCryptHashData(
                hash,
                const_cast<PUCHAR>(data),
                static_cast<ULONG>(size),
                0) < 0 ||
            BCryptFinishHash(
                hash,
                output.data(),
                static_cast<ULONG>(output.size()),
                0) < 0) {
            goto cleanup;
        }
        success = true;

    cleanup:
        if (hash != nullptr) {
            BCryptDestroyHash(hash);
        }
        if (algorithm != nullptr) {
            BCryptCloseAlgorithmProvider(algorithm, 0);
        }
        return success;
    }

    bool CompanionRecordIsPlausible(const ftaa::ProfileFileV1& record)
    {
        if (record.imageSize != g_imageSize ||
            record.registrationRva >= g_imageSize ||
            record.switchHandlerRva >= g_imageSize ||
            record.taaWrapperRva >= g_imageSize ||
            record.sharpenWrapperRva >= g_imageSize ||
            record.taaWrapperRva == record.sharpenWrapperRva ||
            record.taaActionId == 0 || record.sharpenActionId == 0 ||
            record.taaActionId == record.sharpenActionId ||
            record.actionOwnerOffset == 0 || record.actionOwnerOffset > 0x200 ||
            record.actionOwnerOffset % sizeof(void*) != 0 ||
            record.switchHandlerVtableOffset == 0 ||
            record.switchHandlerVtableOffset > 0x400 ||
            record.switchHandlerVtableOffset % sizeof(void*) != 0 ||
            record.settingsPointerOffset < sizeof(void*) ||
            record.settingsPointerOffset > 0x4000 ||
            record.settingsPointerOffset % sizeof(void*) != 0 ||
            record.temporalAaFlagOffset == 0 ||
            record.temporalAaFlagOffset > 0x4000 ||
            record.postProcessSharpenFlagOffset == 0 ||
            record.postProcessSharpenFlagOffset > 0x4000 ||
            record.temporalAaFlagOffset == record.postProcessSharpenFlagOffset) {
            return false;
        }

        const std::uint32_t flagDistance =
            record.temporalAaFlagOffset > record.postProcessSharpenFlagOffset
                ? record.temporalAaFlagOffset - record.postProcessSharpenFlagOffset
                : record.postProcessSharpenFlagOffset - record.temporalAaFlagOffset;
        if (flagDistance > 0x100) {
            return false;
        }

        if (record.rendererAccessMode == ftaa::ProfileRendererAccessMode::VirtualGetter) {
            if (record.getRendererVtableOffset == 0 ||
                record.getRendererVtableOffset > 0x400 ||
                record.getRendererVtableOffset % sizeof(void*) != 0 ||
                record.rendererPointerOffset != 0) {
                return false;
            }
        }
        else if (record.rendererAccessMode ==
                 ftaa::ProfileRendererAccessMode::DirectOwnerPointer) {
            if (record.rendererPointerOffset == 0 ||
                record.rendererPointerOffset > 0x400 ||
                record.rendererPointerOffset % sizeof(void*) != 0 ||
                record.getRendererVtableOffset != 0) {
                return false;
            }
        }
        else {
            return false;
        }

        return IsInsideExecutableRange(
                   g_imageBase + static_cast<std::uintptr_t>(record.registrationRva),
                   kHookLength) &&
            IsInsideExecutableRange(
                   g_imageBase + static_cast<std::uintptr_t>(record.switchHandlerRva), 1) &&
            IsInsideExecutableRange(
                   g_imageBase + static_cast<std::uintptr_t>(record.taaWrapperRva), 34) &&
            IsInsideExecutableRange(
                   g_imageBase + static_cast<std::uintptr_t>(record.sharpenWrapperRva), 34);
    }

    bool CompanionRecordMatchesAdaptive(
        const ftaa::ProfileFileV1& record,
        const RuntimeProfile& adaptive)
    {
        const RendererAccessMode expectedMode =
            record.rendererAccessMode == ftaa::ProfileRendererAccessMode::VirtualGetter
                ? RendererAccessMode::VirtualGetter
                : RendererAccessMode::DirectOwnerPointer;
        return adaptive.rendererAccessMode == expectedMode &&
            adaptive.registrationAddress - g_imageBase == record.registrationRva &&
            adaptive.switchHandlerAddress - g_imageBase == record.switchHandlerRva &&
            adaptive.taaWrapperAddress - g_imageBase == record.taaWrapperRva &&
            adaptive.sharpenWrapperAddress - g_imageBase == record.sharpenWrapperRva &&
            adaptive.actionOwnerOffset == record.actionOwnerOffset &&
            adaptive.getRendererVtableOffset == record.getRendererVtableOffset &&
            adaptive.rendererPointerOffset == record.rendererPointerOffset &&
            adaptive.switchHandlerVtableOffset == record.switchHandlerVtableOffset &&
            adaptive.settingsPointerOffset == record.settingsPointerOffset &&
            adaptive.temporalAaFlagOffset == record.temporalAaFlagOffset &&
            adaptive.postProcessSharpenFlagOffset == record.postProcessSharpenFlagOffset &&
            adaptive.taaActionId == record.taaActionId &&
            adaptive.sharpenActionId == record.sharpenActionId;
    }

    CompanionProfileResult TrySelectCompanionProfile(
        const ExecutableIdentity& identity)
    {
        const std::wstring profilePath =
            GetCompanionSiblingPath(L"CrimsonDesertFTAA.profile");
        const HANDLE file = CreateFileW(
            profilePath.c_str(),
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN,
            nullptr);
        if (file == INVALID_HANDLE_VALUE) {
            const DWORD openError = GetLastError();
            if (openError == ERROR_FILE_NOT_FOUND || openError == ERROR_PATH_NOT_FOUND) {
                Log("No updater-generated CrimsonDesertFTAA.profile was found beside the ASI.");
                return CompanionProfileResult::Missing;
            }
            Log("Could not open CrimsonDesertFTAA.profile (Windows error %lu).", openError);
            return CompanionProfileResult::Invalid;
        }

        LARGE_INTEGER fileSize{};
        ftaa::ProfileFileV1 record{};
        DWORD bytesRead = 0;
        const bool readSucceeded =
            GetFileSizeEx(file, &fileSize) != FALSE &&
            fileSize.QuadPart == static_cast<LONGLONG>(sizeof(record)) &&
            ReadFile(
                file,
                &record,
                static_cast<DWORD>(sizeof(record)),
                &bytesRead,
                nullptr) != FALSE &&
            bytesRead == static_cast<DWORD>(sizeof(record));
        CloseHandle(file);
        if (!readSucceeded) {
            Log("CrimsonDesertFTAA.profile has an invalid size or could not be read completely.");
            return CompanionProfileResult::Invalid;
        }

        if (record.magic != ftaa::kProfileMagic ||
            record.formatMajor != ftaa::kProfileFormatMajor ||
            record.formatMinor != ftaa::kProfileFormatMinor ||
            record.structureSize != static_cast<std::uint32_t>(sizeof(record)) ||
            record.featureFlags != ftaa::kProfileRequiredFeatures ||
            record.reserved0 != 0 ||
            !std::all_of(
                record.reserved1.begin(),
                record.reserved1.end(),
                [](std::uint8_t value) { return value == 0; })) {
            Log("CrimsonDesertFTAA.profile has an unsupported or malformed header.");
            return CompanionProfileResult::Invalid;
        }

        std::array<std::uint8_t, 32> calculatedProfileHash{};
        if (!CalculateCompanionBufferSha256(
                reinterpret_cast<const std::uint8_t*>(&record),
                ftaa::kProfileHashedSize,
                calculatedProfileHash) ||
            calculatedProfileHash != record.profileSha256) {
            Log("CrimsonDesertFTAA.profile failed its SHA-256 integrity check.");
            return CompanionProfileResult::Invalid;
        }

        if (record.executableFileSize != identity.fileSize ||
            record.imageSize != g_imageSize ||
            record.executableSha256 != identity.sha256) {
            Log(
                "CrimsonDesertFTAA.profile targets a different CrimsonDesert.exe; "
                "run the companion updater again.");
            return CompanionProfileResult::DifferentExecutable;
        }
        if (!CompanionRecordIsPlausible(record)) {
            Log("CrimsonDesertFTAA.profile contains an implausible address or structure offset.");
            return CompanionProfileResult::Invalid;
        }

        RuntimeProfile adaptive{};
        Log("Re-running the in-process structural locator to verify the updater profile.");
        if (!ResolveAdaptiveProfile(adaptive) ||
            !CompanionRecordMatchesAdaptive(record, adaptive)) {
            Log(
                "The in-process locator did not exactly reproduce the updater profile; "
                "the plugin is inactive.");
            return CompanionProfileResult::Invalid;
        }

        g_profile = adaptive;
        Log("Updater profile identity, integrity, bounds, and structural checks passed.");
        return CompanionProfileResult::Valid;
    }

    bool SelectCompanionRuntimeProfile()
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
            if (ResolveAdaptiveProfile(adaptive) && AdaptiveProfileMatchesKnown(adaptive)) {
                Log("Adaptive locator self-test matched every known renderer landmark.");
                LogProfile(adaptive, "Adaptive self-test");
            }
            else {
                Log("Adaptive self-test did not match; the exact known profile remains active.");
            }
            return true;
        }

        Log(
            "Unrecognized CrimsonDesert.exe: file size %llu, image size 0x%X, SHA-256 %s.",
            static_cast<unsigned long long>(identity.fileSize),
            g_imageSize,
            digest.c_str());
        Log("Checking for an updater-generated, executable-bound profile.");
        if (TrySelectCompanionProfile(identity) != CompanionProfileResult::Valid) {
            Log(
                "No valid companion profile is available; the plugin is inactive "
                "and made no memory changes.");
            return false;
        }

        LogProfile(g_profile, "Updater-verified adaptive");
        return true;
    }

    DWORD WINAPI InitializeCompanionPlugin(void*)
    {
        if (!IsCrimsonDesertHostProcess()) {
            return 0;
        }

        InitializeLogPath();
        const bool logWasReset = ResetLogForCurrentLaunch();
        Log("CrimsonDesertFTAA 0.4.0 companion-updater test loaded.");
        if (!logWasReset) {
            Log("Warning: the log could not be truncated at launch; new messages are being appended.");
        }

        g_imageBase = reinterpret_cast<std::uintptr_t>(GetModuleHandleW(nullptr));
        if (g_imageBase == 0) {
            Log("Could not resolve the main module; plugin is inactive.");
            return 0;
        }
        if (!ParseLoadedImage() || !SelectCompanionRuntimeProfile()) {
            Log("Build/profile verification failed; plugin is inactive.");
            return 0;
        }
        if (!InstallRegistrationHook()) {
            Log("Hook installation failed; plugin is inactive.");
            return 0;
        }

        constexpr DWORD pollIntervalMilliseconds = 250;
        constexpr DWORD maximumAttempts =
            (10 * 60 * 1000) / pollIntervalMilliseconds;
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
        const HANDLE thread =
            CreateThread(nullptr, 0, InitializeCompanionPlugin, nullptr, 0, nullptr);
        if (thread != nullptr) {
            CloseHandle(thread);
        }
    }
    return TRUE;
}
