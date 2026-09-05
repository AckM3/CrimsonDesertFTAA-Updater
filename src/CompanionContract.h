#pragma once

#include "ProfileFormat.h"

#include <array>
#include <cstddef>
#include <cstdint>

namespace ftaa
{
    inline constexpr char kCompanionContractExportName[] =
        "CrimsonDesertFTAACompanionContract";

    inline constexpr std::array<char, 16> kCompanionContractMagic = {
        'F', 'T', 'A', 'A', 'C', 'O', 'M', 'P',
        'A', 'T', 'V', '1', '\0', '\0', '\0', '\0'};
    inline constexpr std::uint16_t kCompanionContractMajor = 1;
    inline constexpr std::uint16_t kCompanionContractMinor = 0;

    inline constexpr std::uint8_t kCompanionAsiVersionMajor = 0;
    inline constexpr std::uint8_t kCompanionAsiVersionMinor = 4;
    inline constexpr std::uint8_t kCompanionAsiVersionPatch = 0;

    inline constexpr std::uint32_t kCompanionCapabilityProfileReader = 0x00000001;
    inline constexpr std::uint32_t kCompanionCapabilityIndependentRescan = 0x00000002;
    inline constexpr std::uint32_t kCompanionRequiredCapabilities =
        kCompanionCapabilityProfileReader |
        kCompanionCapabilityIndependentRescan;

#pragma pack(push, 1)
    // Exported by the matching ASI as a data symbol. The updater parses this
    // record directly from the PE file without loading or executing the ASI.
    struct CompanionContractV1
    {
        std::array<char, 16> magic{};
        std::uint16_t contractMajor = 0;
        std::uint16_t contractMinor = 0;
        std::uint32_t structureSize = 0;
        std::uint16_t profileFormatMajor = 0;
        std::uint16_t profileFormatMinor = 0;
        std::uint32_t profileStructureSize = 0;
        std::uint8_t requiredProfileFeatures = 0;
        std::uint8_t asiVersionMajor = 0;
        std::uint8_t asiVersionMinor = 0;
        std::uint8_t asiVersionPatch = 0;
        std::uint32_t capabilities = 0;
        std::array<std::uint8_t, 24> reserved{};
    };
#pragma pack(pop)

    inline constexpr CompanionContractV1 kCompanionContractV1 = {
        kCompanionContractMagic,
        kCompanionContractMajor,
        kCompanionContractMinor,
        static_cast<std::uint32_t>(sizeof(CompanionContractV1)),
        kProfileFormatMajor,
        kProfileFormatMinor,
        static_cast<std::uint32_t>(sizeof(ProfileFileV1)),
        kProfileRequiredFeatures,
        kCompanionAsiVersionMajor,
        kCompanionAsiVersionMinor,
        kCompanionAsiVersionPatch,
        kCompanionRequiredCapabilities,
        {}};

    static_assert(sizeof(CompanionContractV1) == 64);
}
