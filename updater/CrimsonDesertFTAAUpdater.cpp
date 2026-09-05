#include "CompanionAsiValidator.h"
#include "OfflinePeScanner.h"
#include "ProfileFormat.h"

#include <Windows.h>
#include <bcrypt.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <limits>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace
{
    constexpr wchar_t kGameExecutableName[] = L"CrimsonDesert.exe";
    constexpr wchar_t kAsiName[] = L"CrimsonDesertFTAA.asi";
    constexpr wchar_t kLegacyAsiName[] = L"CrimsonDesertTAA.asi";
    constexpr wchar_t kProfileName[] = L"CrimsonDesertFTAA.profile";
    constexpr wchar_t kUpdaterLogName[] = L"CrimsonDesertFTAA-Updater.log";
    constexpr wchar_t kDisabledBackupSuffix[] = L".disabled-backup";
    constexpr char kUpdaterVersion[] = "0.4.0";
    constexpr int kEmbeddedAsiResourceId = 101;

    class MappedReadOnlyFile
    {
    public:
        MappedReadOnlyFile() = default;
        MappedReadOnlyFile(const MappedReadOnlyFile&) = delete;
        MappedReadOnlyFile& operator=(const MappedReadOnlyFile&) = delete;

        ~MappedReadOnlyFile()
        {
            if (view_ != nullptr) {
                UnmapViewOfFile(view_);
            }
            if (mapping_ != nullptr) {
                CloseHandle(mapping_);
            }
            if (file_ != INVALID_HANDLE_VALUE) {
                CloseHandle(file_);
            }
        }

        bool Open(
            const std::filesystem::path& path,
            std::string_view fileLabel,
            std::string& error)
        {
            file_ = CreateFileW(
                path.c_str(),
                GENERIC_READ,
                FILE_SHARE_READ,
                nullptr,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN,
                nullptr);
            if (file_ == INVALID_HANDLE_VALUE) {
                error = "Could not open " + std::string(fileLabel) +
                    " for read-only access (Windows error " +
                    std::to_string(GetLastError()) + ").";
                return false;
            }

            LARGE_INTEGER size{};
            if (!GetFileSizeEx(file_, &size) || size.QuadPart <= 0 ||
                static_cast<unsigned long long>(size.QuadPart) >
                    static_cast<unsigned long long>(SIZE_MAX)) {
                error = std::string(fileLabel) +
                    " has an invalid or unsupported file size.";
                return false;
            }
            size_ = static_cast<std::uint64_t>(size.QuadPart);

            mapping_ = CreateFileMappingW(file_, nullptr, PAGE_READONLY, 0, 0, nullptr);
            if (mapping_ == nullptr) {
                error = "Could not create a read-only mapping for " +
                    std::string(fileLabel) + " (Windows error " +
                    std::to_string(GetLastError()) + ").";
                return false;
            }
            view_ = static_cast<const std::uint8_t*>(
                MapViewOfFile(mapping_, FILE_MAP_READ, 0, 0, 0));
            if (view_ == nullptr) {
                error = "Could not map " + std::string(fileLabel) +
                    " for reading (Windows error " +
                    std::to_string(GetLastError()) + ").";
                return false;
            }
            return true;
        }

        std::span<const std::uint8_t> Bytes() const
        {
            return {view_, static_cast<std::size_t>(size_)};
        }

        std::uint64_t Size() const { return size_; }

    private:
        HANDLE file_ = INVALID_HANDLE_VALUE;
        HANDLE mapping_ = nullptr;
        const std::uint8_t* view_ = nullptr;
        std::uint64_t size_ = 0;
    };

    struct Options
    {
        std::filesystem::path input;
        bool scanOnly = false;
        bool verifyEmbedded = false;
        bool pauseAtEnd = true;
        bool showHelp = false;
        bool valid = true;
        std::string error;
    };

    std::filesystem::path ModulePath()
    {
        std::vector<wchar_t> buffer(32768);
        const DWORD length = GetModuleFileNameW(
            nullptr, buffer.data(), static_cast<DWORD>(buffer.size()));
        if (length == 0 || length >= buffer.size()) {
            return {};
        }
        return std::filesystem::path(std::wstring(buffer.data(), length));
    }

    std::string WideToUtf8(const std::wstring& value)
    {
        if (value.empty()) {
            return {};
        }
        const int length = WideCharToMultiByte(
            CP_UTF8,
            WC_ERR_INVALID_CHARS,
            value.data(),
            static_cast<int>(value.size()),
            nullptr,
            0,
            nullptr,
            nullptr);
        if (length <= 0) {
            return "<path conversion failed>";
        }
        std::string output(static_cast<std::size_t>(length), '\0');
        WideCharToMultiByte(
            CP_UTF8,
            WC_ERR_INVALID_CHARS,
            value.data(),
            static_cast<int>(value.size()),
            output.data(),
            length,
            nullptr,
            nullptr);
        return output;
    }

    std::string PathUtf8(const std::filesystem::path& path)
    {
        return WideToUtf8(path.wstring());
    }

    std::string FormatSha256(const std::array<std::uint8_t, 32>& digest)
    {
        constexpr char digits[] = "0123456789ABCDEF";
        std::string output(digest.size() * 2, '0');
        for (std::size_t index = 0; index < digest.size(); ++index) {
            output[index * 2] = digits[digest[index] >> 4];
            output[index * 2 + 1] = digits[digest[index] & 0x0F];
        }
        return output;
    }

    std::string Hex(std::uint64_t value)
    {
        char buffer[32]{};
        sprintf_s(
            buffer,
            sizeof(buffer),
            "0x%llX",
            static_cast<unsigned long long>(value));
        return buffer;
    }

    bool CalculateSha256(
        std::span<const std::uint8_t> input,
        std::array<std::uint8_t, 32>& output,
        std::string& error)
    {
        BCRYPT_ALG_HANDLE algorithm = nullptr;
        BCRYPT_HASH_HANDLE hash = nullptr;
        std::vector<std::uint8_t> hashObject;
        bool success = false;

        DWORD objectSize = 0;
        DWORD hashSize = 0;
        DWORD returned = 0;
        if (BCryptOpenAlgorithmProvider(
                &algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) < 0 ||
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
            error = "Windows SHA-256 initialization failed.";
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
            error = "Windows could not create a SHA-256 context.";
            goto cleanup;
        }

        {
            constexpr std::size_t chunkSize = 16 * 1024 * 1024;
            std::size_t offset = 0;
            while (offset < input.size()) {
                const std::size_t remaining = input.size() - offset;
                const ULONG current = static_cast<ULONG>(
                    std::min<std::size_t>(remaining, chunkSize));
                if (BCryptHashData(
                        hash,
                        const_cast<PUCHAR>(input.data() + offset),
                        current,
                        0) < 0) {
                    error = "Windows failed while calculating SHA-256.";
                    goto cleanup;
                }
                offset += current;
            }
        }

        if (BCryptFinishHash(
                hash,
                output.data(),
                static_cast<ULONG>(output.size()),
                0) < 0) {
            error = "Windows could not finalize SHA-256.";
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

    bool GetEmbeddedCompanionAsi(
        std::span<const std::uint8_t>& bytes,
        std::string& error)
    {
        const HMODULE module = GetModuleHandleW(nullptr);
        const HRSRC resource = FindResourceW(
            module,
            MAKEINTRESOURCEW(kEmbeddedAsiResourceId),
            RT_RCDATA);
        if (resource == nullptr) {
            error = "The updater does not contain its companion ASI resource (Windows error " +
                std::to_string(GetLastError()) + ").";
            return false;
        }

        const DWORD size = SizeofResource(module, resource);
        const HGLOBAL loaded = LoadResource(module, resource);
        const void* data = loaded == nullptr ? nullptr : LockResource(loaded);
        if (size == 0 || data == nullptr) {
            error = "The embedded companion ASI resource is empty or unreadable.";
            return false;
        }

        bytes = {
            static_cast<const std::uint8_t*>(data),
            static_cast<std::size_t>(size)};
        return true;
    }

    std::string CompanionVersionString(const ftaa::CompanionContractV1& contract)
    {
        return std::to_string(contract.asiVersionMajor) + "." +
            std::to_string(contract.asiVersionMinor) + "." +
            std::to_string(contract.asiVersionPatch);
    }

    bool ReadAndValidateEmbeddedCompanion(
        std::span<const std::uint8_t>& asiBytes,
        ftaa::CompanionContractV1& contract,
        std::array<std::uint8_t, 32>& sha256,
        std::vector<std::string>& report,
        std::string& error)
    {
        if (!GetEmbeddedCompanionAsi(asiBytes, error)) {
            return false;
        }

        const ftaa::CompanionAsiValidationResult validation =
            ftaa::ValidateCompanionAsi(asiBytes);
        report.insert(
            report.end(),
            validation.diagnostics.begin(),
            validation.diagnostics.end());
        if (!validation.success) {
            error =
                "The ASI embedded in this updater failed its compatibility self-test. "
                "Rebuild the complete package; no game files were changed.";
            return false;
        }
        if (!CalculateSha256(asiBytes, sha256, error)) {
            error = "Could not hash the ASI embedded in this updater.";
            return false;
        }

        contract = validation.contract;
        report.emplace_back("Embedded ASI file size: " +
            std::to_string(asiBytes.size()) + " bytes");
        report.emplace_back("Embedded ASI SHA-256: " + FormatSha256(sha256));
        report.emplace_back(
            "Embedded ASI companion version: " + CompanionVersionString(contract));
        return true;
    }

    Options ParseOptions(int argc, wchar_t** argv)
    {
        Options options{};
        options.pauseAtEnd = argc == 1;
        for (int index = 1; index < argc; ++index) {
            const std::wstring argument = argv[index];
            if (argument == L"--scan-only") {
                options.scanOnly = true;
            }
            else if (argument == L"--verify-embedded") {
                options.verifyEmbedded = true;
            }
            else if (argument == L"--no-pause") {
                options.pauseAtEnd = false;
            }
            else if (argument == L"--help" || argument == L"-h" || argument == L"/?") {
                options.showHelp = true;
            }
            else if (!argument.empty() && argument[0] == L'-') {
                options.valid = false;
                options.error = "Unknown option: " + WideToUtf8(argument);
                return options;
            }
            else if (options.input.empty()) {
                options.input = argument;
            }
            else {
                options.valid = false;
                options.error = "Only one game path may be supplied.";
                return options;
            }
        }
        if (options.scanOnly && options.verifyEmbedded) {
            options.valid = false;
            options.error = "--scan-only and --verify-embedded cannot be combined.";
        }
        if (options.verifyEmbedded && !options.input.empty()) {
            options.valid = false;
            options.error = "--verify-embedded does not accept a game path.";
        }
        return options;
    }

    std::filesystem::path LocateGameExecutable(
        const std::filesystem::path& updaterDirectory,
        const std::filesystem::path& input)
    {
        std::vector<std::filesystem::path> candidates;
        if (!input.empty()) {
            if (_wcsicmp(input.filename().c_str(), kGameExecutableName) == 0) {
                candidates.push_back(input);
            }
            else {
                candidates.push_back(input / L"bin64" / kGameExecutableName);
                candidates.push_back(input / kGameExecutableName);
            }
        }
        else {
            candidates.push_back(updaterDirectory / kGameExecutableName);
            candidates.push_back(updaterDirectory / L"bin64" / kGameExecutableName);
            candidates.push_back(updaterDirectory.parent_path() / L"bin64" / kGameExecutableName);
        }

        std::error_code error;
        for (const auto& candidate : candidates) {
            if (std::filesystem::is_regular_file(candidate, error)) {
                return std::filesystem::absolute(candidate, error).lexically_normal();
            }
            error.clear();
        }
        return {};
    }

    bool WriteAll(HANDLE file, const void* data, std::size_t size)
    {
        const auto* cursor = static_cast<const std::uint8_t*>(data);
        while (size != 0) {
            const DWORD current = static_cast<DWORD>(
                std::min<std::size_t>(size, std::numeric_limits<DWORD>::max()));
            DWORD written = 0;
            if (!WriteFile(file, cursor, current, &written, nullptr) || written != current) {
                return false;
            }
            cursor += written;
            size -= written;
        }
        return true;
    }

    std::filesystem::path UniqueSiblingPath(
        const std::filesystem::path& path,
        std::wstring_view suffix)
    {
        std::error_code fileError;
        for (unsigned int index = 0; index < 10000; ++index) {
            std::filesystem::path candidate = path;
            candidate += suffix;
            if (index != 0) {
                candidate += L"." + std::to_wstring(index);
            }
            const bool exists = std::filesystem::exists(candidate, fileError);
            if (fileError) {
                return {};
            }
            if (!exists) {
                return candidate;
            }
        }
        return {};
    }

    bool WriteNewFileFlushed(
        const std::filesystem::path& path,
        std::span<const std::uint8_t> bytes,
        std::string& error)
    {
        const HANDLE file = CreateFileW(
            path.c_str(),
            GENERIC_WRITE,
            0,
            nullptr,
            CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL,
            nullptr);
        if (file == INVALID_HANDLE_VALUE) {
            error = "Could not create " + PathUtf8(path) + " (Windows error " +
                std::to_string(GetLastError()) + ").";
            return false;
        }

        const bool wrote = WriteAll(file, bytes.data(), bytes.size());
        const bool flushed = wrote && FlushFileBuffers(file) != FALSE;
        const DWORD writeError = wrote && flushed ? ERROR_SUCCESS : GetLastError();
        CloseHandle(file);
        if (!wrote || !flushed) {
            DeleteFileW(path.c_str());
            error = "Could not completely write " + PathUtf8(path) +
                " (Windows error " + std::to_string(writeError) + ").";
            return false;
        }
        return true;
    }

    bool FileMatchesBytes(
        const std::filesystem::path& path,
        std::span<const std::uint8_t> expected,
        bool& exists,
        bool& matches,
        std::string& error)
    {
        exists = false;
        matches = false;
        std::error_code fileError;
        if (!std::filesystem::exists(path, fileError)) {
            if (fileError) {
                error = "Could not inspect " + PathUtf8(path) + ".";
                return false;
            }
            return true;
        }
        if (!std::filesystem::is_regular_file(path, fileError) || fileError) {
            error = PathUtf8(path) + " exists but is not a regular file.";
            return false;
        }
        exists = true;

        MappedReadOnlyFile mapped;
        if (!mapped.Open(path, PathUtf8(path), error)) {
            return false;
        }
        matches = mapped.Size() == expected.size() &&
            std::equal(expected.begin(), expected.end(), mapped.Bytes().begin());
        return true;
    }

    struct MovedFile
    {
        std::filesystem::path original;
        std::filesystem::path backup;
    };

    struct AsiInstallTransaction
    {
        std::filesystem::path target;
        std::vector<MovedFile> moved;
        bool installedNewAsi = false;
    };

    void RollBackMoves(
        std::vector<MovedFile>& moved,
        std::vector<std::string>& report)
    {
        for (auto iterator = moved.rbegin(); iterator != moved.rend(); ++iterator) {
            if (MoveFileExW(
                    iterator->backup.c_str(),
                    iterator->original.c_str(),
                    MOVEFILE_WRITE_THROUGH)) {
                report.emplace_back(
                    "Rollback restored: " + PathUtf8(iterator->original));
            }
            else {
                report.emplace_back(
                    "Warning: rollback could not restore " +
                    PathUtf8(iterator->original) + " from " +
                    PathUtf8(iterator->backup) + ".");
            }
        }
        moved.clear();
    }

    bool MoveInstalledAsiToBackup(
        const std::filesystem::path& path,
        std::vector<MovedFile>& moved,
        std::vector<std::string>& report,
        std::string& error)
    {
        std::error_code fileError;
        if (!std::filesystem::exists(path, fileError)) {
            if (fileError) {
                error = "Could not inspect installed ASI " + PathUtf8(path) + ".";
                return false;
            }
            return true;
        }
        if (!std::filesystem::is_regular_file(path, fileError) || fileError) {
            error = PathUtf8(path) + " exists but is not a regular file.";
            return false;
        }

        const std::filesystem::path backup =
            UniqueSiblingPath(path, kDisabledBackupSuffix);
        if (backup.empty()) {
            error = "Could not choose a unique backup name for " + PathUtf8(path) + ".";
            return false;
        }
        if (!MoveFileExW(path.c_str(), backup.c_str(), MOVEFILE_WRITE_THROUGH)) {
            error = "Could not back up " + PathUtf8(path) +
                ". Close Crimson Desert and try again (Windows error " +
                std::to_string(GetLastError()) + ").";
            return false;
        }

        moved.push_back({path, backup});
        report.emplace_back("Disabled ASI backup: " + PathUtf8(backup));
        return true;
    }

    bool InstallEmbeddedCompanionAsi(
        const std::filesystem::path& gameDirectory,
        std::span<const std::uint8_t> asiBytes,
        AsiInstallTransaction& transaction,
        std::vector<std::string>& report,
        std::string& error)
    {
        const std::filesystem::path target = gameDirectory / kAsiName;
        const std::filesystem::path legacy = gameDirectory / kLegacyAsiName;
        transaction = {};
        transaction.target = target;

        bool targetExists = false;
        bool targetMatches = false;
        if (!FileMatchesBytes(
                target,
                asiBytes,
                targetExists,
                targetMatches,
                error)) {
            return false;
        }

        std::filesystem::path staged;
        if (!targetMatches) {
            staged = UniqueSiblingPath(target, L".installing");
            if (staged.empty()) {
                error = "Could not choose a temporary ASI installation path.";
                return false;
            }
            if (!WriteNewFileFlushed(staged, asiBytes, error)) {
                return false;
            }

            bool stagedExists = false;
            bool stagedMatches = false;
            if (!FileMatchesBytes(
                    staged,
                    asiBytes,
                    stagedExists,
                    stagedMatches,
                    error) ||
                !stagedExists || !stagedMatches) {
                DeleteFileW(staged.c_str());
                if (error.empty()) {
                    error = "The staged companion ASI failed byte-for-byte verification.";
                }
                return false;
            }
        }

        if (!MoveInstalledAsiToBackup(legacy, transaction.moved, report, error)) {
            DeleteFileW(staged.c_str());
            return false;
        }
        if (!targetMatches && targetExists &&
            !MoveInstalledAsiToBackup(target, transaction.moved, report, error)) {
            DeleteFileW(staged.c_str());
            RollBackMoves(transaction.moved, report);
            return false;
        }

        if (!targetMatches &&
            !MoveFileExW(staged.c_str(), target.c_str(), MOVEFILE_WRITE_THROUGH)) {
            const DWORD installError = GetLastError();
            DeleteFileW(staged.c_str());
            RollBackMoves(transaction.moved, report);
            error = "Could not install the matching CrimsonDesertFTAA.asi (Windows error " +
                std::to_string(installError) + ").";
            return false;
        }
        transaction.installedNewAsi = !targetMatches;

        if (!targetMatches) {
            bool installedExists = false;
            bool installedMatches = false;
            std::string verificationError;
            if (!FileMatchesBytes(
                    target,
                    asiBytes,
                    installedExists,
                    installedMatches,
                    verificationError) ||
                !installedExists || !installedMatches) {
                DeleteFileW(target.c_str());
                transaction.installedNewAsi = false;
                RollBackMoves(transaction.moved, report);
                error = verificationError.empty()
                    ? "The installed companion ASI failed byte-for-byte verification."
                    : verificationError;
                return false;
            }
        }

        if (targetMatches) {
            report.emplace_back("Installed ASI already matches the embedded companion.");
        }
        else {
            report.emplace_back("Installed matching ASI: " + PathUtf8(target));
        }
        return true;
    }

    void RollBackAsiInstallation(
        AsiInstallTransaction& transaction,
        std::vector<std::string>& report)
    {
        if (transaction.installedNewAsi) {
            if (DeleteFileW(transaction.target.c_str())) {
                report.emplace_back(
                    "Rollback removed newly installed ASI: " +
                    PathUtf8(transaction.target));
            }
            else {
                report.emplace_back(
                    "Warning: rollback could not remove newly installed ASI " +
                    PathUtf8(transaction.target) + ".");
            }
            transaction.installedNewAsi = false;
        }
        RollBackMoves(transaction.moved, report);
    }

    bool StageProfile(
        const std::filesystem::path& path,
        const ftaa::ProfileFileV1& profile,
        std::filesystem::path& staged,
        std::string& error)
    {
        staged = UniqueSiblingPath(path, L".installing");
        if (staged.empty()) {
            error = "Could not choose a temporary profile path.";
            return false;
        }
        return WriteNewFileFlushed(
            staged,
            {reinterpret_cast<const std::uint8_t*>(&profile), sizeof(profile)},
            error);
    }

    bool CommitStagedProfile(
        const std::filesystem::path& staged,
        const std::filesystem::path& path,
        std::string& error)
    {
        if (!MoveFileExW(
                staged.c_str(),
                path.c_str(),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
            const DWORD moveError = GetLastError();
            DeleteFileW(staged.c_str());
            error = "Could not atomically replace the profile (Windows error " +
                std::to_string(moveError) + ").";
            return false;
        }
        return true;
    }

    void WriteReport(
        const std::filesystem::path& path,
        const std::vector<std::string>& lines)
    {
        std::ofstream report(path, std::ios::binary | std::ios::trunc);
        if (!report) {
            return;
        }

        SYSTEMTIME time{};
        GetLocalTime(&time);
        char timestamp[64]{};
        sprintf_s(
            timestamp,
            "%04u-%02u-%02u %02u:%02u:%02u",
            time.wYear,
            time.wMonth,
            time.wDay,
            time.wHour,
            time.wMinute,
            time.wSecond);
        report << "Crimson Desert FTAA Companion Updater " << kUpdaterVersion << "\r\n";
        report << "Generated: " << timestamp << "\r\n\r\n";
        for (const std::string& line : lines) {
            report << line << "\r\n";
        }
    }

    void PauseIfRequested(bool pause)
    {
        if (!pause) {
            return;
        }
        std::cout << "\nPress Enter to close." << std::flush;
        std::string ignored;
        std::getline(std::cin, ignored);
    }

    int Finish(
        int code,
        bool pause,
        const std::filesystem::path& reportPath,
        const std::vector<std::string>& report)
    {
        WriteReport(reportPath, report);
        PauseIfRequested(pause);
        return code;
    }
}

int wmain(int argc, wchar_t** argv)
{
    SetConsoleOutputCP(CP_UTF8);
    std::cout << "Crimson Desert FTAA Companion Updater " << kUpdaterVersion << "\n";
    std::cout
        << "Self-contained ASI updater with a read-only game executable scan.\n"
        << "CrimsonDesert.exe is never modified.\n\n";

    const std::filesystem::path updaterPath = ModulePath();
    const std::filesystem::path updaterDirectory = updaterPath.parent_path();
    const std::filesystem::path reportPath = updaterDirectory / kUpdaterLogName;
    std::vector<std::string> report;
    report.emplace_back(
        "Game scanner mode: read-only; ASI/profile installer mode: fail-closed");

    const Options options = ParseOptions(argc, argv);
    if (!options.valid) {
        std::cerr << "Error: " << options.error << "\n";
        report.emplace_back("Failure: " + options.error);
        return Finish(2, options.pauseAtEnd, reportPath, report);
    }
    if (options.showHelp) {
        std::cout
            << "Usage: CrimsonDesertFTAA-Updater.exe [game directory or executable] "
               "[--scan-only] [--no-pause]\n"
            << "       CrimsonDesertFTAA-Updater.exe --verify-embedded [--no-pause]\n\n"
            << "The updater contains and installs its matching CrimsonDesertFTAA.asi.\n"
            << "Place it in bin64, or pass the game directory as an argument.\n";
        return Finish(0, options.pauseAtEnd, reportPath, report);
    }

    std::span<const std::uint8_t> embeddedAsi;
    ftaa::CompanionContractV1 embeddedContract{};
    std::array<std::uint8_t, 32> embeddedAsiSha256{};
    std::string error;
    if (!ReadAndValidateEmbeddedCompanion(
            embeddedAsi,
            embeddedContract,
            embeddedAsiSha256,
            report,
            error)) {
        std::cerr << "Error: " << error << "\n";
        report.emplace_back("Failure: " + error);
        return Finish(4, options.pauseAtEnd, reportPath, report);
    }
    std::cout << "Embedded companion ASI "
              << CompanionVersionString(embeddedContract)
              << " passed its compatibility self-test.\n";
    if (options.verifyEmbedded) {
        report.emplace_back(
            "Success: embedded companion ASI passed its compatibility self-test.");
        return Finish(0, options.pauseAtEnd, reportPath, report);
    }

    const std::filesystem::path executable =
        LocateGameExecutable(updaterDirectory, options.input);
    if (executable.empty()) {
        const std::string message =
            "CrimsonDesert.exe was not found. Place this updater in "
            "bin64, or pass the Crimson Desert game directory as an argument.";
        std::cerr << "Error: " << message << "\n";
        report.emplace_back("Failure: " + message);
        return Finish(3, options.pauseAtEnd, reportPath, report);
    }
    if (_wcsicmp(executable.filename().c_str(), kGameExecutableName) != 0) {
        const std::string message = "Refusing to scan a file not named CrimsonDesert.exe.";
        std::cerr << "Error: " << message << "\n";
        report.emplace_back("Failure: " + message);
        return Finish(3, options.pauseAtEnd, reportPath, report);
    }

    std::cout << "Executable: " << PathUtf8(executable) << "\n";
    report.emplace_back("Executable: " + PathUtf8(executable));

    MappedReadOnlyFile mapped;
    if (!mapped.Open(executable, "CrimsonDesert.exe", error)) {
        std::cerr << "Error: " << error << "\n";
        report.emplace_back("Failure: " + error);
        return Finish(5, options.pauseAtEnd, reportPath, report);
    }
    report.emplace_back("File size: " + std::to_string(mapped.Size()) + " bytes");

    std::cout << "Calculating SHA-256...\n";
    std::array<std::uint8_t, 32> executableSha256{};
    if (!CalculateSha256(mapped.Bytes(), executableSha256, error)) {
        std::cerr << "Error: " << error << "\n";
        report.emplace_back("Failure: " + error);
        return Finish(6, options.pauseAtEnd, reportPath, report);
    }
    const std::string digest = FormatSha256(executableSha256);
    std::cout << "SHA-256: " << digest << "\n";
    report.emplace_back("SHA-256: " + digest);

    std::cout << "Resolving and cross-validating the native FTAA path...\n";
    const ftaa::OfflineScanResult scan = ftaa::ScanCrimsonDesertImage(mapped.Bytes());
    report.insert(report.end(), scan.diagnostics.begin(), scan.diagnostics.end());
    if (!scan.success) {
        const std::string message =
            "The required renderer path was missing or ambiguous. The existing profile "
            "was left untouched.";
        std::cerr << "\nScan failed: " << message << "\n";
        report.emplace_back("Failure: " + message);
        return Finish(7, options.pauseAtEnd, reportPath, report);
    }

    const ftaa::OfflineProfile& found = scan.profile;
    report.emplace_back("Image size: " + Hex(found.imageSize));
    report.emplace_back("Registration RVA: " + Hex(found.registrationRva));
    report.emplace_back("Native switch RVA: " + Hex(found.switchHandlerRva));
    report.emplace_back("TAA wrapper RVA: " + Hex(found.taaWrapperRva));
    report.emplace_back("Sharpen wrapper RVA: " + Hex(found.sharpenWrapperRva));
    report.emplace_back("Action owner offset: +" + Hex(found.actionOwnerOffset));
    report.emplace_back(
        std::string("Renderer access: ") +
        (found.rendererAccessMode == ftaa::ProfileRendererAccessMode::VirtualGetter
             ? "virtual getter +" + Hex(found.getRendererVtableOffset)
             : "direct owner pointer +" + Hex(found.rendererPointerOffset)));
    report.emplace_back(
        "Switch vtable offset: +" + Hex(found.switchHandlerVtableOffset));
    report.emplace_back("Settings pointer offset: +" + Hex(found.settingsPointerOffset));
    report.emplace_back(
        "TAA/sharpen flag offsets: +" + Hex(found.temporalAaFlagOffset) + "/+" +
        Hex(found.postProcessSharpenFlagOffset));
    report.emplace_back(
        "TAA/sharpen action IDs: " + Hex(found.taaActionId) + "/" +
        Hex(found.sharpenActionId));

    std::cout << "Validated one unique, internally consistent profile.\n";
    std::cout << "  Registration RVA: " << Hex(found.registrationRva) << "\n";
    std::cout << "  Native switch RVA: " << Hex(found.switchHandlerRva) << "\n";
    std::cout << "  Settings/flags: +" << Hex(found.settingsPointerOffset) << " / +"
              << Hex(found.temporalAaFlagOffset) << " / +"
              << Hex(found.postProcessSharpenFlagOffset) << "\n";

    if (options.scanOnly) {
        std::cout << "\nScan-only mode: no ASI or profile file was changed.\n";
        report.emplace_back(
            "Success: scan-only mode; no ASI or profile file was changed.");
        return Finish(0, options.pauseAtEnd, reportPath, report);
    }

    ftaa::ProfileFileV1 profile{};
    profile.magic = ftaa::kProfileMagic;
    profile.formatMajor = ftaa::kProfileFormatMajor;
    profile.formatMinor = ftaa::kProfileFormatMinor;
    profile.structureSize = static_cast<std::uint32_t>(sizeof(profile));
    profile.imageSize = found.imageSize;
    profile.executableFileSize = mapped.Size();
    profile.executableSha256 = executableSha256;
    profile.rendererAccessMode = found.rendererAccessMode;
    profile.taaActionId = found.taaActionId;
    profile.sharpenActionId = found.sharpenActionId;
    profile.featureFlags = ftaa::kProfileRequiredFeatures;
    profile.registrationRva = found.registrationRva;
    profile.switchHandlerRva = found.switchHandlerRva;
    profile.taaWrapperRva = found.taaWrapperRva;
    profile.sharpenWrapperRva = found.sharpenWrapperRva;
    profile.actionOwnerOffset = found.actionOwnerOffset;
    profile.getRendererVtableOffset = found.getRendererVtableOffset;
    profile.rendererPointerOffset = found.rendererPointerOffset;
    profile.switchHandlerVtableOffset = found.switchHandlerVtableOffset;
    profile.settingsPointerOffset = found.settingsPointerOffset;
    profile.temporalAaFlagOffset = found.temporalAaFlagOffset;
    profile.postProcessSharpenFlagOffset = found.postProcessSharpenFlagOffset;

    if (!CalculateSha256(
            {reinterpret_cast<const std::uint8_t*>(&profile), ftaa::kProfileHashedSize},
            profile.profileSha256,
            error)) {
        std::cerr << "Error: " << error << "\n";
        report.emplace_back("Failure: " + error);
        return Finish(8, options.pauseAtEnd, reportPath, report);
    }

    const std::filesystem::path gameDirectory = executable.parent_path();
    const std::filesystem::path profilePath = gameDirectory / kProfileName;
    std::filesystem::path stagedProfile;
    if (!StageProfile(profilePath, profile, stagedProfile, error)) {
        std::cerr << "Error: " << error << "\n";
        report.emplace_back("Failure: " + error);
        return Finish(9, options.pauseAtEnd, reportPath, report);
    }

    std::cout << "Installing the matching companion ASI...\n";
    AsiInstallTransaction asiTransaction{};
    if (!InstallEmbeddedCompanionAsi(
            gameDirectory,
            embeddedAsi,
            asiTransaction,
            report,
            error)) {
        DeleteFileW(stagedProfile.c_str());
        std::cerr << "Error: " << error << "\n";
        report.emplace_back("Failure: " + error);
        return Finish(10, options.pauseAtEnd, reportPath, report);
    }

    if (!CommitStagedProfile(stagedProfile, profilePath, error)) {
        RollBackAsiInstallation(asiTransaction, report);
        std::cerr << "Error: " << error << "\n";
        report.emplace_back(
            "Failure: the profile could not be committed, so the ASI installation "
            "was rolled back. " + error);
        return Finish(11, options.pauseAtEnd, reportPath, report);
    }

    const std::filesystem::path asiPath = gameDirectory / kAsiName;
    std::cout << "\nSuccess: the matching ASI was installed and "
              << PathUtf8(profilePath) << " was updated atomically.\n";
    std::cout << "CrimsonDesert.exe was not modified.\n";
    report.emplace_back("ASI: " + PathUtf8(asiPath));
    report.emplace_back("Profile: " + PathUtf8(profilePath));
    report.emplace_back(
        "Success: matching ASI installed and profile updated atomically; "
        "CrimsonDesert.exe was not modified.");
    return Finish(0, options.pauseAtEnd, reportPath, report);
}
