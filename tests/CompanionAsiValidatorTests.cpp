#include "CompanionAsiValidator.h"

#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <string_view>
#include <vector>

namespace
{
    constexpr std::uint32_t kSectionRva = 0x1000;
    constexpr std::uint32_t kSectionRaw = 0x400;

    std::size_t Raw(std::uint32_t rva)
    {
        return kSectionRaw + (rva - kSectionRva);
    }

    template <typename T>
    void Put(std::vector<std::uint8_t>& bytes, std::size_t offset, const T& value)
    {
        std::memcpy(bytes.data() + offset, &value, sizeof(value));
    }

    void PutString(
        std::vector<std::uint8_t>& bytes,
        std::uint32_t rva,
        std::string_view value)
    {
        std::memcpy(bytes.data() + Raw(rva), value.data(), value.size());
        bytes[Raw(rva) + value.size()] = 0;
    }

    std::vector<std::uint8_t> MakeCompanionFixture()
    {
        std::vector<std::uint8_t> bytes(0x1400, 0);
        Put(bytes, 0x00, std::uint16_t{0x5A4D});
        Put(bytes, 0x3C, std::uint32_t{0x80});
        Put(bytes, 0x80, std::uint32_t{0x00004550});
        Put(bytes, 0x84, std::uint16_t{0x8664});
        Put(bytes, 0x86, std::uint16_t{1});
        Put(bytes, 0x94, std::uint16_t{0xF0});
        Put(bytes, 0x96, std::uint16_t{0x2022});

        constexpr std::size_t optional = 0x98;
        Put(bytes, optional, std::uint16_t{0x020B});
        Put(bytes, optional + 56, std::uint32_t{0x2000});
        Put(bytes, optional + 60, std::uint32_t{0x400});
        Put(bytes, optional + 108, std::uint32_t{16});
        Put(bytes, optional + 112, std::uint32_t{0x1000});
        Put(bytes, optional + 116, std::uint32_t{0x200});

        constexpr std::size_t section = optional + 0xF0;
        std::memcpy(bytes.data() + section, ".rdata", 6);
        Put(bytes, section + 8, std::uint32_t{0x1000});
        Put(bytes, section + 12, kSectionRva);
        Put(bytes, section + 16, std::uint32_t{0x1000});
        Put(bytes, section + 20, kSectionRaw);
        Put(bytes, section + 36, std::uint32_t{0x40000040});

        constexpr std::uint32_t exportRva = 0x1000;
        constexpr std::uint32_t functionsRva = 0x1040;
        constexpr std::uint32_t namesRva = 0x1050;
        constexpr std::uint32_t ordinalsRva = 0x1060;
        constexpr std::uint32_t dllNameRva = 0x1070;
        constexpr std::uint32_t exportNameRva = 0x1080;
        constexpr std::uint32_t contractRva = 0x1300;

        Put(bytes, Raw(exportRva) + 12, dllNameRva);
        Put(bytes, Raw(exportRva) + 16, std::uint32_t{1});
        Put(bytes, Raw(exportRva) + 20, std::uint32_t{1});
        Put(bytes, Raw(exportRva) + 24, std::uint32_t{1});
        Put(bytes, Raw(exportRva) + 28, functionsRva);
        Put(bytes, Raw(exportRva) + 32, namesRva);
        Put(bytes, Raw(exportRva) + 36, ordinalsRva);
        Put(bytes, Raw(functionsRva), contractRva);
        Put(bytes, Raw(namesRva), exportNameRva);
        Put(bytes, Raw(ordinalsRva), std::uint16_t{0});
        PutString(bytes, dllNameRva, "CrimsonDesertFTAA.asi");
        PutString(bytes, exportNameRva, ftaa::kCompanionContractExportName);
        Put(bytes, Raw(contractRva), ftaa::kCompanionContractV1);
        return bytes;
    }
}

int main()
{
    {
        const auto fixture = MakeCompanionFixture();
        const auto result = ftaa::ValidateCompanionAsi(fixture);
        assert(result.success);
        assert(result.contract.asiVersionMajor == 0);
        assert(result.contract.asiVersionMinor == 4);
        assert(result.contract.asiVersionPatch == 0);
    }

    {
        auto legacyAsi = MakeCompanionFixture();
        legacyAsi[Raw(0x1080)] = 'X';
        assert(!ftaa::ValidateCompanionAsi(legacyAsi).success);
    }

    {
        auto wrongProfileReader = MakeCompanionFixture();
        ftaa::CompanionContractV1 contract = ftaa::kCompanionContractV1;
        ++contract.profileFormatMajor;
        Put(wrongProfileReader, Raw(0x1300), contract);
        assert(!ftaa::ValidateCompanionAsi(wrongProfileReader).success);
    }

    {
        auto missingSafetyCapability = MakeCompanionFixture();
        ftaa::CompanionContractV1 contract = ftaa::kCompanionContractV1;
        contract.capabilities = ftaa::kCompanionCapabilityProfileReader;
        Put(missingSafetyCapability, Raw(0x1300), contract);
        assert(!ftaa::ValidateCompanionAsi(missingSafetyCapability).success);
    }

    {
        auto x86Asi = MakeCompanionFixture();
        Put(x86Asi, 0x84, std::uint16_t{0x014C});
        assert(!ftaa::ValidateCompanionAsi(x86Asi).success);
    }

    std::cout << "CompanionAsiValidator tests passed\n";
    return 0;
}
