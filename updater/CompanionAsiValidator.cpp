#include "CompanionAsiValidator.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace ftaa
{
    namespace
    {
        constexpr std::uint16_t kDosMagic = 0x5A4D;
        constexpr std::uint32_t kPeSignature = 0x00004550;
        constexpr std::uint16_t kMachineAmd64 = 0x8664;
        constexpr std::uint16_t kPe32PlusMagic = 0x020B;
        constexpr std::uint16_t kImageFileDll = 0x2000;
        constexpr std::size_t kSectionHeaderSize = 40;
        constexpr std::size_t kExportDirectorySize = 40;
        constexpr std::uint32_t kMaximumExportCount = 65536;

        bool RangeFits(std::size_t offset, std::size_t length, std::size_t size)
        {
            return offset <= size && length <= size - offset;
        }

        template <typename T>
        bool Read(
            std::span<const std::uint8_t> bytes,
            std::size_t offset,
            T& output)
        {
            if (!RangeFits(offset, sizeof(T), bytes.size())) {
                return false;
            }
            std::memcpy(&output, bytes.data() + offset, sizeof(T));
            return true;
        }

        struct Section
        {
            std::uint32_t virtualSize = 0;
            std::uint32_t virtualAddress = 0;
            std::uint32_t rawSize = 0;
            std::uint32_t rawOffset = 0;
        };

        class PeFile
        {
        public:
            explicit PeFile(std::span<const std::uint8_t> bytes) : bytes_(bytes) {}

            bool Parse(std::string& error)
            {
                std::uint16_t dosMagic = 0;
                std::uint32_t peOffset32 = 0;
                if (!Read(bytes_, 0, dosMagic) || dosMagic != kDosMagic ||
                    !Read(bytes_, 0x3C, peOffset32)) {
                    error = "ASI is not a valid DOS/PE file.";
                    return false;
                }

                const std::size_t peOffset = peOffset32;
                std::uint32_t signature = 0;
                std::uint16_t machine = 0;
                std::uint16_t sectionCount = 0;
                std::uint16_t optionalSize = 0;
                std::uint16_t characteristics = 0;
                if (!Read(bytes_, peOffset, signature) || signature != kPeSignature ||
                    !Read(bytes_, peOffset + 4, machine) ||
                    !Read(bytes_, peOffset + 6, sectionCount) ||
                    !Read(bytes_, peOffset + 20, optionalSize) ||
                    !Read(bytes_, peOffset + 22, characteristics)) {
                    error = "ASI has a truncated or invalid PE header.";
                    return false;
                }
                if (machine != kMachineAmd64 || (characteristics & kImageFileDll) == 0) {
                    error = "ASI is not an AMD64 DLL.";
                    return false;
                }
                if (sectionCount == 0 || sectionCount > 96 || optionalSize < 120) {
                    error = "ASI has an unsupported PE layout.";
                    return false;
                }

                const std::size_t optionalOffset = peOffset + 24;
                std::uint16_t optionalMagic = 0;
                std::uint32_t sizeOfHeaders = 0;
                std::uint32_t directoryCount = 0;
                if (!RangeFits(optionalOffset, optionalSize, bytes_.size()) ||
                    !Read(bytes_, optionalOffset, optionalMagic) ||
                    optionalMagic != kPe32PlusMagic ||
                    !Read(bytes_, optionalOffset + 60, sizeOfHeaders) ||
                    !Read(bytes_, optionalOffset + 108, directoryCount) ||
                    directoryCount == 0 ||
                    !Read(bytes_, optionalOffset + 112, exportRva_) ||
                    !Read(bytes_, optionalOffset + 116, exportSize_)) {
                    error = "ASI is not a complete PE32+ image.";
                    return false;
                }
                if (exportRva_ == 0 || exportSize_ < kExportDirectorySize) {
                    error = "ASI does not export the FTAA companion contract.";
                    return false;
                }
                sizeOfHeaders_ = sizeOfHeaders;

                const std::size_t sectionTable = optionalOffset + optionalSize;
                if (!RangeFits(
                        sectionTable,
                        static_cast<std::size_t>(sectionCount) * kSectionHeaderSize,
                        bytes_.size())) {
                    error = "ASI section table is truncated.";
                    return false;
                }

                sections_.reserve(sectionCount);
                for (std::uint16_t index = 0; index < sectionCount; ++index) {
                    const std::size_t header =
                        sectionTable + static_cast<std::size_t>(index) * kSectionHeaderSize;
                    Section section{};
                    if (!Read(bytes_, header + 8, section.virtualSize) ||
                        !Read(bytes_, header + 12, section.virtualAddress) ||
                        !Read(bytes_, header + 16, section.rawSize) ||
                        !Read(bytes_, header + 20, section.rawOffset) ||
                        !RangeFits(section.rawOffset, section.rawSize, bytes_.size())) {
                        error = "ASI contains an invalid section mapping.";
                        return false;
                    }
                    sections_.push_back(section);
                }
                return true;
            }

            std::optional<std::size_t> RvaToOffset(
                std::uint32_t rva,
                std::size_t length) const
            {
                if (rva < sizeOfHeaders_) {
                    const std::size_t offset = rva;
                    if (RangeFits(offset, length, bytes_.size()) &&
                        length <= static_cast<std::size_t>(sizeOfHeaders_ - rva)) {
                        return offset;
                    }
                    return std::nullopt;
                }

                for (const Section& section : sections_) {
                    const std::uint64_t sectionSpan =
                        std::max(section.virtualSize, section.rawSize);
                    if (rva < section.virtualAddress ||
                        static_cast<std::uint64_t>(rva - section.virtualAddress) >=
                            sectionSpan) {
                        continue;
                    }
                    const std::uint64_t delta = rva - section.virtualAddress;
                    if (delta > section.rawSize || length > section.rawSize - delta) {
                        return std::nullopt;
                    }
                    const std::uint64_t offset64 = section.rawOffset + delta;
                    if (offset64 > std::numeric_limits<std::size_t>::max()) {
                        return std::nullopt;
                    }
                    const std::size_t offset = static_cast<std::size_t>(offset64);
                    if (!RangeFits(offset, length, bytes_.size())) {
                        return std::nullopt;
                    }
                    return offset;
                }
                return std::nullopt;
            }

            bool ReadRva(std::uint32_t rva, void* output, std::size_t length) const
            {
                const auto offset = RvaToOffset(rva, length);
                if (!offset.has_value()) {
                    return false;
                }
                std::memcpy(output, bytes_.data() + *offset, length);
                return true;
            }

            bool ReadExportName(std::uint32_t rva, std::string& output) const
            {
                output.clear();
                constexpr std::size_t maximumNameLength = 256;
                for (std::size_t index = 0; index < maximumNameLength; ++index) {
                    if (rva > std::numeric_limits<std::uint32_t>::max() - index) {
                        return false;
                    }
                    const auto offset = RvaToOffset(
                        static_cast<std::uint32_t>(rva + index), 1);
                    if (!offset.has_value()) {
                        return false;
                    }
                    const char character = static_cast<char>(bytes_[*offset]);
                    if (character == '\0') {
                        return !output.empty();
                    }
                    output.push_back(character);
                }
                return false;
            }

            std::uint32_t ExportRva() const { return exportRva_; }
            std::uint32_t ExportSize() const { return exportSize_; }

        private:
            std::span<const std::uint8_t> bytes_;
            std::vector<Section> sections_;
            std::uint32_t sizeOfHeaders_ = 0;
            std::uint32_t exportRva_ = 0;
            std::uint32_t exportSize_ = 0;
        };

        bool ContractIsSupported(
            const CompanionContractV1& contract,
            std::string& error)
        {
            if (contract.magic != kCompanionContractMagic ||
                contract.contractMajor != kCompanionContractMajor ||
                contract.structureSize != sizeof(CompanionContractV1)) {
                error = "ASI exported an unsupported FTAA companion contract.";
                return false;
            }
            if (contract.profileFormatMajor != kProfileFormatMajor ||
                contract.profileFormatMinor != kProfileFormatMinor ||
                contract.profileStructureSize != sizeof(ProfileFileV1) ||
                contract.requiredProfileFeatures != kProfileRequiredFeatures) {
                error = "ASI cannot consume the profile format produced by this updater.";
                return false;
            }
            if ((contract.capabilities & kCompanionRequiredCapabilities) !=
                kCompanionRequiredCapabilities) {
                error = "ASI lacks a required companion safety capability.";
                return false;
            }
            if (!std::all_of(
                    contract.reserved.begin(),
                    contract.reserved.end(),
                    [](std::uint8_t value) { return value == 0; })) {
                error = "ASI companion contract contains nonzero reserved data.";
                return false;
            }
            return true;
        }
    }

    CompanionAsiValidationResult ValidateCompanionAsi(
        std::span<const std::uint8_t> fileBytes)
    {
        CompanionAsiValidationResult result{};
        PeFile image(fileBytes);
        std::string error;
        if (!image.Parse(error)) {
            result.diagnostics.push_back(error);
            return result;
        }

        const auto exportOffset =
            image.RvaToOffset(image.ExportRva(), kExportDirectorySize);
        if (!exportOffset.has_value()) {
            result.diagnostics.emplace_back("ASI export directory is not file-backed.");
            return result;
        }

        std::uint32_t functionCount = 0;
        std::uint32_t nameCount = 0;
        std::uint32_t functionsRva = 0;
        std::uint32_t namesRva = 0;
        std::uint32_t ordinalsRva = 0;
        const auto bytes = fileBytes;
        if (!Read(bytes, *exportOffset + 20, functionCount) ||
            !Read(bytes, *exportOffset + 24, nameCount) ||
            !Read(bytes, *exportOffset + 28, functionsRva) ||
            !Read(bytes, *exportOffset + 32, namesRva) ||
            !Read(bytes, *exportOffset + 36, ordinalsRva) ||
            functionCount == 0 || nameCount == 0 ||
            functionCount > kMaximumExportCount || nameCount > kMaximumExportCount) {
            result.diagnostics.emplace_back("ASI export table is invalid or empty.");
            return result;
        }

        const auto functionsOffset = image.RvaToOffset(
            functionsRva, static_cast<std::size_t>(functionCount) * sizeof(std::uint32_t));
        const auto namesOffset = image.RvaToOffset(
            namesRva, static_cast<std::size_t>(nameCount) * sizeof(std::uint32_t));
        const auto ordinalsOffset = image.RvaToOffset(
            ordinalsRva, static_cast<std::size_t>(nameCount) * sizeof(std::uint16_t));
        if (!functionsOffset.has_value() || !namesOffset.has_value() ||
            !ordinalsOffset.has_value()) {
            result.diagnostics.emplace_back("ASI export arrays are invalid.");
            return result;
        }

        std::uint32_t contractRva = 0;
        std::size_t matches = 0;
        for (std::uint32_t index = 0; index < nameCount; ++index) {
            std::uint32_t nameRva = 0;
            std::uint16_t ordinal = 0;
            if (!Read(
                    bytes,
                    *namesOffset + static_cast<std::size_t>(index) * sizeof(nameRva),
                    nameRva) ||
                !Read(
                    bytes,
                    *ordinalsOffset + static_cast<std::size_t>(index) * sizeof(ordinal),
                    ordinal)) {
                result.diagnostics.emplace_back("ASI export entry is truncated.");
                return result;
            }

            std::string name;
            if (!image.ReadExportName(nameRva, name)) {
                result.diagnostics.emplace_back("ASI contains an invalid export name.");
                return result;
            }
            if (name != kCompanionContractExportName) {
                continue;
            }
            if (ordinal >= functionCount ||
                !Read(
                    bytes,
                    *functionsOffset + static_cast<std::size_t>(ordinal) * sizeof(contractRva),
                    contractRva)) {
                result.diagnostics.emplace_back("ASI companion export has an invalid ordinal.");
                return result;
            }
            ++matches;
        }

        if (matches != 1 || contractRva == 0) {
            result.diagnostics.emplace_back(
                "ASI does not contain exactly one FTAA companion contract export.");
            return result;
        }

        const std::uint64_t exportEnd =
            static_cast<std::uint64_t>(image.ExportRva()) + image.ExportSize();
        if (contractRva >= image.ExportRva() && contractRva < exportEnd) {
            result.diagnostics.emplace_back("ASI companion export is a forwarder, not data.");
            return result;
        }

        if (!image.ReadRva(contractRva, &result.contract, sizeof(result.contract))) {
            result.diagnostics.emplace_back("ASI companion contract is not file-backed.");
            return result;
        }
        if (!ContractIsSupported(result.contract, error)) {
            result.diagnostics.push_back(error);
            return result;
        }

        result.success = true;
        result.diagnostics.emplace_back(
            "Validated the exported FTAA profile-reader contract without loading the ASI.");
        return result;
    }
}
