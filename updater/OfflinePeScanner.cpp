#include "OfflinePeScanner.h"

#include <algorithm>
#include <array>
#include <cstring>
#include <limits>
#include <optional>
#include <sstream>
#include <utility>

namespace ftaa
{
    namespace
    {
        constexpr std::uint16_t kDosSignature = 0x5A4D;
        constexpr std::uint32_t kPeSignature = 0x00004550;
        constexpr std::uint16_t kAmd64Machine = 0x8664;
        constexpr std::uint16_t kPe32PlusMagic = 0x020B;
        constexpr std::uint32_t kExecutableSection = 0x20000000;
        constexpr std::size_t kSectionHeaderSize = 40;
        constexpr std::size_t kRuntimeFunctionSize = 12;
        constexpr std::size_t kHookLength = 15;

        constexpr char kTaaActionName[] =
            "PearlAbyssEngine.Debug.ToggleRenderingFeature.TemporalAA";
        constexpr char kSharpenActionName[] =
            "PearlAbyssEngine.Debug.ToggleRenderingFeature.PostProcessSharpen";
        constexpr char kTaaEnabledText[] = "Temporal AA is enabled";
        constexpr char kTaaDisabledText[] = "Temporal AA is disabled";
        constexpr char kSharpenEnabledText[] = "Post Process Sharpen is enabled";
        constexpr char kSharpenDisabledText[] = "Post Process Sharpen is disabled";

        constexpr std::array<std::uint8_t, kHookLength> kSafeRegistrationPrefix = {
            0x48, 0x89, 0x5C, 0x24, 0x08,
            0x48, 0x89, 0x74, 0x24, 0x10,
            0x48, 0x89, 0x7C, 0x24, 0x18};

        struct Section
        {
            std::uint32_t virtualAddress = 0;
            std::uint32_t virtualSize = 0;
            std::uint32_t rawOffset = 0;
            std::uint32_t rawSize = 0;
            bool executable = false;
        };

        struct RuntimeFunction
        {
            std::uint32_t begin = 0;
            std::uint32_t end = 0;
        };

        struct ActionWrapperInfo
        {
            ProfileRendererAccessMode rendererAccessMode =
                ProfileRendererAccessMode::VirtualGetter;
            std::uint32_t registrationRva = 0;
            std::uint32_t wrapperRva = 0;
            std::uint32_t gateObjectOffset = 0;
            std::uint32_t gateFlagOffset = 0;
            std::uint32_t actionOwnerOffset = 0;
            std::uint32_t getRendererVtableOffset = 0;
            std::uint32_t rendererPointerOffset = 0;
            std::uint32_t switchHandlerVtableOffset = 0;
            std::uint8_t actionId = 0;
        };

        struct ToggleInfo
        {
            std::uint32_t functionRva = 0;
            std::uint32_t blockRva = 0;
            std::uint32_t settingsPointerOffset = 0;
            std::uint32_t flagOffset = 0;
        };

        bool AddWithin(std::uint64_t left, std::uint64_t right, std::uint64_t limit)
        {
            return left <= limit && right <= limit - left;
        }

        std::string Hex(std::uint64_t value)
        {
            std::ostringstream stream;
            stream << "0x" << std::hex << std::uppercase << value;
            return stream.str();
        }

        class PeImage
        {
        public:
            explicit PeImage(std::span<const std::uint8_t> bytes) : bytes_(bytes) {}

            bool Parse(std::vector<std::string>& diagnostics)
            {
                if (bytes_.size() < 0x100 || ReadU16(0).value_or(0) != kDosSignature) {
                    diagnostics.emplace_back("The file does not have a valid DOS header.");
                    return false;
                }

                const auto peOffset = ReadU32(0x3C);
                if (!peOffset || *peOffset > 0x100000 ||
                    !AddWithin(*peOffset, 24, bytes_.size()) ||
                    ReadU32(*peOffset).value_or(0) != kPeSignature) {
                    diagnostics.emplace_back("The file does not have a valid PE header.");
                    return false;
                }

                const std::size_t fileHeader = static_cast<std::size_t>(*peOffset) + 4;
                const auto machine = ReadU16(fileHeader);
                const auto sectionCount = ReadU16(fileHeader + 2);
                const auto optionalSize = ReadU16(fileHeader + 16);
                if (!machine || *machine != kAmd64Machine || !sectionCount ||
                    *sectionCount == 0 || *sectionCount > 96 || !optionalSize) {
                    diagnostics.emplace_back("The executable is not a plausible AMD64 PE image.");
                    return false;
                }

                const std::size_t optionalHeader = fileHeader + 20;
                if (!AddWithin(optionalHeader, *optionalSize, bytes_.size()) ||
                    ReadU16(optionalHeader).value_or(0) != kPe32PlusMagic ||
                    *optionalSize < 136) {
                    diagnostics.emplace_back("The PE32+ optional header is invalid or truncated.");
                    return false;
                }

                imageSize_ = ReadU32(optionalHeader + 56).value_or(0);
                sizeOfHeaders_ = ReadU32(optionalHeader + 60).value_or(0);
                const std::uint32_t directoryCount =
                    ReadU32(optionalHeader + 108).value_or(0);
                if (imageSize_ < 0x10000 || sizeOfHeaders_ == 0 ||
                    sizeOfHeaders_ > bytes_.size() || directoryCount <= 3) {
                    diagnostics.emplace_back("The PE image size or data directories are invalid.");
                    return false;
                }

                const std::size_t sectionTable = optionalHeader + *optionalSize;
                const std::size_t sectionBytes =
                    static_cast<std::size_t>(*sectionCount) * kSectionHeaderSize;
                if (!AddWithin(sectionTable, sectionBytes, bytes_.size())) {
                    diagnostics.emplace_back("The PE section table is truncated.");
                    return false;
                }

                sections_.clear();
                sections_.reserve(*sectionCount);
                for (std::size_t index = 0; index < *sectionCount; ++index) {
                    const std::size_t cursor = sectionTable + index * kSectionHeaderSize;
                    Section section{};
                    section.virtualSize = ReadU32(cursor + 8).value_or(0);
                    section.virtualAddress = ReadU32(cursor + 12).value_or(0);
                    section.rawSize = ReadU32(cursor + 16).value_or(0);
                    section.rawOffset = ReadU32(cursor + 20).value_or(0);
                    section.executable =
                        (ReadU32(cursor + 36).value_or(0) & kExecutableSection) != 0;

                    if (section.virtualAddress >= imageSize_) {
                        diagnostics.emplace_back("A PE section begins outside SizeOfImage.");
                        return false;
                    }
                    if (section.rawSize != 0 &&
                        !AddWithin(section.rawOffset, section.rawSize, bytes_.size())) {
                        diagnostics.emplace_back("A PE section points beyond the end of the file.");
                        return false;
                    }
                    sections_.push_back(section);
                }

                const std::size_t exceptionDirectory = optionalHeader + 112 + 3 * 8;
                const std::uint32_t exceptionRva =
                    ReadU32(exceptionDirectory).value_or(0);
                const std::uint32_t exceptionSize =
                    ReadU32(exceptionDirectory + 4).value_or(0);
                if (exceptionRva == 0 || exceptionSize < kRuntimeFunctionSize ||
                    exceptionSize % kRuntimeFunctionSize != 0) {
                    diagnostics.emplace_back("The x64 exception directory is missing or malformed.");
                    return false;
                }

                const auto exceptionBytes = RvaSpan(exceptionRva, exceptionSize);
                if (!exceptionBytes) {
                    diagnostics.emplace_back("The x64 exception directory is not backed by file data.");
                    return false;
                }

                runtimeFunctions_.clear();
                runtimeFunctions_.reserve(exceptionSize / kRuntimeFunctionSize);
                for (std::size_t offset = 0; offset < exceptionSize;
                     offset += kRuntimeFunctionSize) {
                    RuntimeFunction function{};
                    std::memcpy(&function.begin, exceptionBytes->data() + offset, 4);
                    std::memcpy(&function.end, exceptionBytes->data() + offset + 4, 4);
                    if (function.begin == 0 && function.end == 0) {
                        continue;
                    }
                    if (function.begin >= function.end || function.end > imageSize_) {
                        diagnostics.emplace_back("The x64 exception table contains an invalid function range.");
                        return false;
                    }
                    runtimeFunctions_.push_back(function);
                }
                if (runtimeFunctions_.empty()) {
                    diagnostics.emplace_back("The x64 exception table contains no usable function ranges.");
                    return false;
                }

                std::sort(
                    runtimeFunctions_.begin(),
                    runtimeFunctions_.end(),
                    [](const RuntimeFunction& left, const RuntimeFunction& right) {
                        return left.begin < right.begin;
                    });

                parsed_ = true;
                return true;
            }

            std::uint32_t ImageSize() const { return imageSize_; }

            std::optional<std::span<const std::uint8_t>> RvaSpan(
                std::uint32_t rva,
                std::size_t size) const
            {
                if (size > imageSize_ || rva > imageSize_ - size) {
                    return std::nullopt;
                }
                if (rva < sizeOfHeaders_) {
                    if (AddWithin(rva, size, std::min<std::uint64_t>(sizeOfHeaders_, bytes_.size()))) {
                        return bytes_.subspan(rva, size);
                    }
                    return std::nullopt;
                }

                for (const Section& section : sections_) {
                    const std::uint64_t mappedSize =
                        std::max<std::uint64_t>(section.virtualSize, section.rawSize);
                    if (rva < section.virtualAddress ||
                        rva - section.virtualAddress > mappedSize ||
                        size > mappedSize - (rva - section.virtualAddress)) {
                        continue;
                    }

                    const std::uint64_t delta = rva - section.virtualAddress;
                    if (delta > section.rawSize || size > section.rawSize - delta) {
                        return std::nullopt;
                    }
                    const std::uint64_t fileOffset = section.rawOffset + delta;
                    if (!AddWithin(fileOffset, size, bytes_.size())) {
                        return std::nullopt;
                    }
                    return bytes_.subspan(static_cast<std::size_t>(fileOffset), size);
                }
                return std::nullopt;
            }

            bool IsExecutableRva(std::uint32_t rva, std::size_t size) const
            {
                for (const Section& section : sections_) {
                    if (!section.executable || rva < section.virtualAddress) {
                        continue;
                    }
                    const std::uint64_t delta = rva - section.virtualAddress;
                    if (delta <= section.rawSize && size <= section.rawSize - delta) {
                        return true;
                    }
                }
                return false;
            }

            std::optional<std::uint32_t> FindUniqueAscii(
                const char* text,
                std::vector<std::string>& diagnostics,
                const char* label) const
            {
                const std::span<const char> needle(text, std::strlen(text) + 1);
                std::size_t matches = 0;
                std::uint32_t matchRva = 0;

                for (const Section& section : sections_) {
                    if (section.executable || section.rawSize < needle.size()) {
                        continue;
                    }
                    const auto haystack = bytes_.subspan(section.rawOffset, section.rawSize);
                    auto cursor = haystack.begin();
                    while (cursor != haystack.end()) {
                        const auto found = std::search(
                            cursor,
                            haystack.end(),
                            reinterpret_cast<const std::uint8_t*>(needle.data()),
                            reinterpret_cast<const std::uint8_t*>(needle.data()) + needle.size());
                        if (found == haystack.end()) {
                            break;
                        }
                        ++matches;
                        matchRva = section.virtualAddress +
                            static_cast<std::uint32_t>(found - haystack.begin());
                        if (matches > 1) {
                            diagnostics.emplace_back(
                                std::string(label) + " string is not unique.");
                            return std::nullopt;
                        }
                        cursor = found + 1;
                    }
                }

                if (matches != 1) {
                    diagnostics.emplace_back(std::string(label) + " string was not found.");
                    return std::nullopt;
                }
                return matchRva;
            }

            std::vector<std::uint32_t> FindRipLeaReferences(
                std::uint32_t targetRva,
                int requiredRex,
                int requiredModRm) const
            {
                std::vector<std::uint32_t> references;
                for (const Section& section : sections_) {
                    if (!section.executable || section.rawSize < 7) {
                        continue;
                    }
                    const auto code = bytes_.subspan(section.rawOffset, section.rawSize);
                    for (std::size_t offset = 0; offset <= code.size() - 7; ++offset) {
                        const auto* instruction = code.data() + offset;
                        const bool isRipLea =
                            instruction[0] >= 0x48 && instruction[0] <= 0x4F &&
                            instruction[1] == 0x8D &&
                            (instruction[2] & 0xC7) == 0x05;
                        if (!isRipLea ||
                            (requiredRex >= 0 && instruction[0] != requiredRex) ||
                            (requiredModRm >= 0 && instruction[2] != requiredModRm)) {
                            continue;
                        }

                        const std::uint32_t instructionRva =
                            section.virtualAddress + static_cast<std::uint32_t>(offset);
                        const auto resolved = ResolveRipTarget(instructionRva, instruction);
                        if (resolved && *resolved == targetRva) {
                            references.push_back(instructionRva);
                        }
                    }
                }
                return references;
            }

            std::optional<RuntimeFunction> FindRuntimeFunction(std::uint32_t rva) const
            {
                const auto upper = std::upper_bound(
                    runtimeFunctions_.begin(),
                    runtimeFunctions_.end(),
                    rva,
                    [](std::uint32_t value, const RuntimeFunction& function) {
                        return value < function.begin;
                    });
                if (upper == runtimeFunctions_.begin()) {
                    return std::nullopt;
                }

                for (auto cursor = upper; cursor != runtimeFunctions_.begin();) {
                    --cursor;
                    if (cursor->begin <= rva && rva < cursor->end) {
                        return *cursor;
                    }
                    if (rva - cursor->begin > 0x10000) {
                        break;
                    }
                }
                return std::nullopt;
            }

            std::optional<std::uint32_t> ResolveRipTarget(
                std::uint32_t instructionRva,
                const std::uint8_t* instruction) const
            {
                std::int32_t displacement = 0;
                std::memcpy(&displacement, instruction + 3, sizeof(displacement));
                const std::int64_t target =
                    static_cast<std::int64_t>(instructionRva) + 7 + displacement;
                if (target < 0 || target >= imageSize_) {
                    return std::nullopt;
                }
                return static_cast<std::uint32_t>(target);
            }

        private:
            std::optional<std::uint16_t> ReadU16(std::size_t offset) const
            {
                if (!AddWithin(offset, sizeof(std::uint16_t), bytes_.size())) {
                    return std::nullopt;
                }
                std::uint16_t value = 0;
                std::memcpy(&value, bytes_.data() + offset, sizeof(value));
                return value;
            }

            std::optional<std::uint32_t> ReadU32(std::size_t offset) const
            {
                if (!AddWithin(offset, sizeof(std::uint32_t), bytes_.size())) {
                    return std::nullopt;
                }
                std::uint32_t value = 0;
                std::memcpy(&value, bytes_.data() + offset, sizeof(value));
                return value;
            }

            std::span<const std::uint8_t> bytes_;
            bool parsed_ = false;
            std::uint32_t imageSize_ = 0;
            std::uint32_t sizeOfHeaders_ = 0;
            std::vector<Section> sections_;
            std::vector<RuntimeFunction> runtimeFunctions_;
        };

        bool ParseActionWrapper(
            const PeImage& image,
            std::uint32_t wrapperRva,
            ActionWrapperInfo& info)
        {
            constexpr std::size_t legacyWrapperSize = 51;
            constexpr std::size_t compactWrapperSize = 34;
            const auto compact = image.RvaSpan(wrapperRva, compactWrapperSize);
            if (!compact || !image.IsExecutableRva(wrapperRva, compactWrapperSize)) {
                return false;
            }
            const auto* code = compact->data();

            bool legacyShape = false;
            const auto legacy = image.RvaSpan(wrapperRva, legacyWrapperSize);
            if (legacy && image.IsExecutableRva(wrapperRva, legacyWrapperSize)) {
                code = legacy->data();
                legacyShape =
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
            }

            code = compact->data();
            const bool compactShape =
                std::memcmp(code, "\x48\x8B\x41", 3) == 0 &&
                std::memcmp(code + 4, "\x48\x8B\x10\x80\x7A", 5) == 0 &&
                code[10] == 0x00 && code[11] == 0x74 && code[12] == 0x14 &&
                std::memcmp(code + 13, "\x48\x8B\x41", 3) == 0 &&
                code[17] == 0xB2 &&
                std::memcmp(code + 19, "\x48\x8B\x48", 3) == 0 &&
                std::memcmp(code + 23, "\x48\x8B\x01\x48\xFF\xA0", 6) == 0 &&
                code[33] == 0xC3;

            if (!legacyShape && !compactShape) {
                return false;
            }

            if (legacyShape) {
                code = legacy->data();
                info.rendererAccessMode = ProfileRendererAccessMode::VirtualGetter;
                info.gateObjectOffset = code[7];
                info.gateFlagOffset = code[13];
                info.actionOwnerOffset = code[20];
                info.getRendererVtableOffset = code[26];
                std::memcpy(&info.switchHandlerVtableOffset, code + 42, 4);
                info.actionId = code[28];
            }
            else {
                info.rendererAccessMode = ProfileRendererAccessMode::DirectOwnerPointer;
                info.gateObjectOffset = code[3];
                info.gateFlagOffset = code[9];
                info.actionOwnerOffset = code[16];
                info.rendererPointerOffset = code[22];
                std::memcpy(&info.switchHandlerVtableOffset, code + 29, 4);
                info.actionId = code[18];
            }

            if (info.gateObjectOffset == 0 || info.gateObjectOffset > 0x200 ||
                info.gateObjectOffset % 8 != 0 ||
                info.gateFlagOffset == 0 || info.gateFlagOffset > 0x100 ||
                info.actionOwnerOffset == 0 || info.actionOwnerOffset > 0x200 ||
                info.actionOwnerOffset % 8 != 0 ||
                info.switchHandlerVtableOffset == 0 ||
                info.switchHandlerVtableOffset > 0x400 ||
                info.switchHandlerVtableOffset % 8 != 0 || info.actionId == 0) {
                return false;
            }

            if (info.rendererAccessMode == ProfileRendererAccessMode::VirtualGetter) {
                if (info.getRendererVtableOffset == 0 ||
                    info.getRendererVtableOffset > 0x400 ||
                    info.getRendererVtableOffset % 8 != 0 ||
                    info.rendererPointerOffset != 0) {
                    return false;
                }
            }
            else if (info.rendererPointerOffset == 0 ||
                     info.rendererPointerOffset > 0x400 ||
                     info.rendererPointerOffset % 8 != 0 ||
                     info.getRendererVtableOffset != 0) {
                return false;
            }

            info.wrapperRva = wrapperRva;
            return true;
        }

        bool ResolveActionWrapper(
            const PeImage& image,
            const char* actionName,
            const char* label,
            ActionWrapperInfo& result,
            std::vector<std::string>& diagnostics)
        {
            const auto actionString = image.FindUniqueAscii(
                actionName, diagnostics, label);
            if (!actionString) {
                return false;
            }

            const auto references = image.FindRipLeaReferences(*actionString, 0x48, 0x15);
            std::vector<ActionWrapperInfo> candidates;
            for (const std::uint32_t reference : references) {
                const auto function = image.FindRuntimeFunction(reference);
                if (!function || function->end <= reference + 7) {
                    continue;
                }

                const std::uint32_t searchEnd = std::min<std::uint32_t>(
                    function->end,
                    reference <= std::numeric_limits<std::uint32_t>::max() - 96
                        ? reference + 96
                        : function->end);
                for (std::uint32_t cursor = reference + 7;
                     cursor <= searchEnd && searchEnd - cursor >= 7;
                     ++cursor) {
                    const auto instruction = image.RvaSpan(cursor, 7);
                    if (!instruction || (*instruction)[0] != 0x48 ||
                        (*instruction)[1] != 0x8D || (*instruction)[2] != 0x0D) {
                        continue;
                    }

                    const auto wrapperRva = image.ResolveRipTarget(
                        cursor, instruction->data());
                    if (!wrapperRva) {
                        continue;
                    }
                    ActionWrapperInfo candidate{};
                    if (!ParseActionWrapper(image, *wrapperRva, candidate)) {
                        continue;
                    }
                    candidate.registrationRva = function->begin;
                    const bool duplicate = std::any_of(
                        candidates.begin(),
                        candidates.end(),
                        [&](const ActionWrapperInfo& existing) {
                            return existing.wrapperRva == candidate.wrapperRva;
                        });
                    if (!duplicate) {
                        candidates.push_back(candidate);
                    }
                }
            }

            if (candidates.size() != 1) {
                diagnostics.emplace_back(
                    std::string(label) + " registration path produced " +
                    std::to_string(candidates.size()) +
                    " semantic candidates; expected exactly one.");
                return false;
            }
            result = candidates.front();
            return true;
        }

        bool ParseToggleBlock(
            const PeImage& image,
            std::uint32_t blockRva,
            std::uint32_t enabledTextRva,
            std::uint32_t disabledTextRva,
            ToggleInfo& info)
        {
            constexpr std::size_t blockSize = 71;
            const auto block = image.RvaSpan(blockRva, blockSize);
            if (!block || !image.IsExecutableRva(blockRva, blockSize)) {
                return false;
            }
            const auto* code = block->data();
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
            std::memcpy(&settingsA, code + 3, 4);
            std::memcpy(&settingsB, code + 26, 4);
            std::memcpy(&flagA, code + (immediateZeroCompare ? 9 : 10), 4);
            std::memcpy(&flagB, code + 19, 4);
            std::memcpy(&flagC, code + 33, 4);

            const auto enabledTarget = image.ResolveRipTarget(blockRva + 57, code + 57);
            const auto disabledTarget = image.ResolveRipTarget(blockRva + 64, code + 64);
            if (settingsA != settingsB || flagA != flagB || flagA != flagC ||
                settingsA < 8 || settingsA > 0x4000 || settingsA % 8 != 0 ||
                flagA == 0 || flagA > 0x4000 ||
                !enabledTarget || *enabledTarget != enabledTextRva ||
                !disabledTarget || *disabledTarget != disabledTextRva) {
                return false;
            }

            info.blockRva = blockRva;
            info.settingsPointerOffset = settingsA;
            info.flagOffset = flagA;
            return true;
        }

        bool ResolveToggle(
            const PeImage& image,
            const char* enabledText,
            const char* disabledText,
            const char* label,
            ToggleInfo& result,
            std::vector<std::string>& diagnostics)
        {
            const auto enabledRva = image.FindUniqueAscii(
                enabledText, diagnostics, (std::string(label) + " enabled-status").c_str());
            const auto disabledRva = image.FindUniqueAscii(
                disabledText, diagnostics, (std::string(label) + " disabled-status").c_str());
            if (!enabledRva || !disabledRva) {
                return false;
            }

            const auto enabledReferences = image.FindRipLeaReferences(*enabledRva, -1, -1);
            std::vector<RuntimeFunction> functions;
            for (const std::uint32_t reference : enabledReferences) {
                const auto function = image.FindRuntimeFunction(reference);
                if (!function || function->end <= function->begin ||
                    function->end - function->begin > 0x10000) {
                    continue;
                }
                const bool duplicate = std::any_of(
                    functions.begin(), functions.end(), [&](const RuntimeFunction& existing) {
                        return existing.begin == function->begin;
                    });
                if (!duplicate) {
                    functions.push_back(*function);
                }
            }

            std::vector<ToggleInfo> candidates;
            for (const RuntimeFunction& function : functions) {
                for (std::uint32_t cursor = function.begin;
                     cursor <= function.end && function.end - cursor >= 71;
                     ++cursor) {
                    ToggleInfo candidate{};
                    if (ParseToggleBlock(
                            image, cursor, *enabledRva, *disabledRva, candidate)) {
                        candidate.functionRva = function.begin;
                        candidates.push_back(candidate);
                    }
                }
            }

            if (candidates.size() != 1) {
                diagnostics.emplace_back(
                    std::string(label) + " native toggle produced " +
                    std::to_string(candidates.size()) +
                    " semantic candidates; expected exactly one.");
                return false;
            }
            result = candidates.front();
            return true;
        }
    }

    OfflineScanResult ScanCrimsonDesertImage(std::span<const std::uint8_t> imageBytes)
    {
        OfflineScanResult output{};
        output.diagnostics.emplace_back("Opening the executable as a read-only PE image.");

        PeImage image(imageBytes);
        if (!image.Parse(output.diagnostics)) {
            return output;
        }
        output.diagnostics.emplace_back(
            "Validated AMD64 PE32+ headers, sections, and x64 exception metadata.");

        ActionWrapperInfo taaAction{};
        ActionWrapperInfo sharpenAction{};
        if (!ResolveActionWrapper(
                image, kTaaActionName, "TemporalAA", taaAction, output.diagnostics) ||
            !ResolveActionWrapper(
                image,
                kSharpenActionName,
                "PostProcessSharpen",
                sharpenAction,
                output.diagnostics)) {
            return output;
        }

        if (taaAction.registrationRva != sharpenAction.registrationRva ||
            taaAction.wrapperRva == sharpenAction.wrapperRva ||
            taaAction.rendererAccessMode != sharpenAction.rendererAccessMode ||
            taaAction.gateObjectOffset != sharpenAction.gateObjectOffset ||
            taaAction.gateFlagOffset != sharpenAction.gateFlagOffset ||
            taaAction.actionOwnerOffset != sharpenAction.actionOwnerOffset ||
            taaAction.getRendererVtableOffset != sharpenAction.getRendererVtableOffset ||
            taaAction.rendererPointerOffset != sharpenAction.rendererPointerOffset ||
            taaAction.switchHandlerVtableOffset != sharpenAction.switchHandlerVtableOffset ||
            taaAction.actionId == sharpenAction.actionId) {
            output.diagnostics.emplace_back(
                "The TAA and sharpening registration paths do not form one consistent family.");
            return output;
        }

        const auto registration = image.RvaSpan(
            taaAction.registrationRva, kSafeRegistrationPrefix.size());
        if (!registration ||
            !image.IsExecutableRva(
                taaAction.registrationRva, kSafeRegistrationPrefix.size()) ||
            !std::equal(
                kSafeRegistrationPrefix.begin(),
                kSafeRegistrationPrefix.end(),
                registration->begin())) {
            output.diagnostics.emplace_back(
                "The registration routine does not have the verified relocation-free hook prefix.");
            return output;
        }
        output.diagnostics.emplace_back(
            "Resolved one mutually consistent TAA/sharpening registration path.");

        ToggleInfo taaToggle{};
        ToggleInfo sharpenToggle{};
        if (!ResolveToggle(
                image,
                kTaaEnabledText,
                kTaaDisabledText,
                "TemporalAA",
                taaToggle,
                output.diagnostics) ||
            !ResolveToggle(
                image,
                kSharpenEnabledText,
                kSharpenDisabledText,
                "PostProcessSharpen",
                sharpenToggle,
                output.diagnostics)) {
            return output;
        }

        const std::uint32_t flagDistance =
            taaToggle.flagOffset > sharpenToggle.flagOffset
                ? taaToggle.flagOffset - sharpenToggle.flagOffset
                : sharpenToggle.flagOffset - taaToggle.flagOffset;
        if (taaToggle.functionRva != sharpenToggle.functionRva ||
            taaToggle.settingsPointerOffset != sharpenToggle.settingsPointerOffset ||
            taaToggle.flagOffset == sharpenToggle.flagOffset || flagDistance > 0x100) {
            output.diagnostics.emplace_back(
                "The TAA and sharpening native switch branches do not agree.");
            return output;
        }
        output.diagnostics.emplace_back(
            "Resolved one mutually consistent native Boolean-toggle path.");

        output.profile.rendererAccessMode = taaAction.rendererAccessMode;
        output.profile.imageSize = image.ImageSize();
        output.profile.registrationRva = taaAction.registrationRva;
        output.profile.switchHandlerRva = taaToggle.functionRva;
        output.profile.taaWrapperRva = taaAction.wrapperRva;
        output.profile.sharpenWrapperRva = sharpenAction.wrapperRva;
        output.profile.actionOwnerOffset = taaAction.actionOwnerOffset;
        output.profile.getRendererVtableOffset = taaAction.getRendererVtableOffset;
        output.profile.rendererPointerOffset = taaAction.rendererPointerOffset;
        output.profile.switchHandlerVtableOffset = taaAction.switchHandlerVtableOffset;
        output.profile.settingsPointerOffset = taaToggle.settingsPointerOffset;
        output.profile.temporalAaFlagOffset = taaToggle.flagOffset;
        output.profile.postProcessSharpenFlagOffset = sharpenToggle.flagOffset;
        output.profile.taaActionId = taaAction.actionId;
        output.profile.sharpenActionId = sharpenAction.actionId;
        output.success = true;

        output.diagnostics.emplace_back(
            "Validated profile: registration " + Hex(output.profile.registrationRva) +
            ", switch " + Hex(output.profile.switchHandlerRva) +
            ", settings +" + Hex(output.profile.settingsPointerOffset) +
            ", flags +" + Hex(output.profile.temporalAaFlagOffset) + "/+" +
            Hex(output.profile.postProcessSharpenFlagOffset) + ".");
        return output;
    }
}
