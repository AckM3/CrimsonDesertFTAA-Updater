#include "OfflinePeScanner.h"

#include <array>
#include <cassert>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <span>
#include <string_view>
#include <vector>

namespace
{
    constexpr std::uint32_t kTextRva = 0x1000;
    constexpr std::uint32_t kTextRaw = 0x400;
    constexpr std::uint32_t kRdataRva = 0x6000;
    constexpr std::uint32_t kRdataRaw = 0x5400;

    std::size_t Raw(std::uint32_t rva)
    {
        if (rva >= kRdataRva) {
            return kRdataRaw + (rva - kRdataRva);
        }
        return kTextRaw + (rva - kTextRva);
    }

    template <typename Container, typename T>
    void Put(Container& bytes, std::size_t offset, T value)
    {
        std::memcpy(bytes.data() + offset, &value, sizeof(value));
    }

    void PutBytes(
        std::vector<std::uint8_t>& bytes,
        std::size_t offset,
        std::span<const std::uint8_t> value)
    {
        std::memcpy(bytes.data() + offset, value.data(), value.size());
    }

    void PutString(
        std::vector<std::uint8_t>& bytes,
        std::uint32_t rva,
        std::string_view value)
    {
        std::memcpy(bytes.data() + Raw(rva), value.data(), value.size());
        bytes[Raw(rva) + value.size()] = 0;
    }

    void PutRipLea(
        std::vector<std::uint8_t>& bytes,
        std::uint32_t instructionRva,
        std::array<std::uint8_t, 3> prefix,
        std::uint32_t targetRva)
    {
        const std::int64_t displacement64 =
            static_cast<std::int64_t>(targetRva) - instructionRva - 7;
        const std::int32_t displacement = static_cast<std::int32_t>(displacement64);
        PutBytes(bytes, Raw(instructionRva), prefix);
        Put(bytes, Raw(instructionRva) + 3, displacement);
    }

    void PutCompactWrapper(
        std::vector<std::uint8_t>& bytes,
        std::uint32_t rva,
        std::uint8_t actionId)
    {
        std::array<std::uint8_t, 34> wrapper = {
            0x48, 0x8B, 0x41, 0x38,
            0x48, 0x8B, 0x10,
            0x80, 0x7A, 0x49, 0x00,
            0x74, 0x14,
            0x48, 0x8B, 0x41, 0x30,
            0xB2, actionId,
            0x48, 0x8B, 0x48, 0x58,
            0x48, 0x8B, 0x01,
            0x48, 0xFF, 0xA0, 0xA0, 0x00, 0x00, 0x00,
            0xC3};
        PutBytes(bytes, Raw(rva), wrapper);
    }

    void PutLegacyWrapper(
        std::vector<std::uint8_t>& bytes,
        std::uint32_t rva,
        std::uint8_t actionId)
    {
        std::array<std::uint8_t, 51> wrapper = {
            0x48, 0x83, 0xEC, 0x28,
            0x48, 0x8B, 0x41, 0x38,
            0x48, 0x8B, 0x10,
            0x80, 0x7A, 0x49, 0x00,
            0x74, 0x1D,
            0x48, 0x8B, 0x49, 0x30,
            0x48, 0x8B, 0x01,
            0xFF, 0x50, 0x48,
            0xB2, actionId,
            0x48, 0x8B, 0xC8,
            0x4C, 0x8B, 0x00,
            0x48, 0x83, 0xC4, 0x28,
            0x49, 0xFF, 0xA0, 0xA0, 0x00, 0x00, 0x00,
            0x48, 0x83, 0xC4, 0x28, 0xC3};
        PutBytes(bytes, Raw(rva), wrapper);
    }

    void PutToggle(
        std::vector<std::uint8_t>& bytes,
        std::uint32_t rva,
        std::uint32_t flagOffset,
        std::uint32_t enabledRva,
        std::uint32_t disabledRva,
        bool immediateCompare,
        std::uint32_t settingsOffset)
    {
        std::array<std::uint8_t, 71> block{};
        const std::array<std::uint8_t, 3> settingsLoad = {0x48, 0x8B, 0x8B};
        const std::array<std::uint8_t, 3> registerCompare = {0x44, 0x38, 0x89};
        const std::array<std::uint8_t, 5> setAndStore = {0x0F, 0x94, 0xC0, 0x88, 0x81};
        const std::array<std::uint8_t, 3> settingsReload = {0x48, 0x8B, 0x83};
        const std::array<std::uint8_t, 3> byteLoad = {0x0F, 0xB6, 0x88};
        const std::array<std::uint8_t, 3> leaRdx = {0x48, 0x8D, 0x15};
        const std::array<std::uint8_t, 3> leaRax = {0x48, 0x8D, 0x05};
        const std::array<std::uint8_t, 6> select = {0x84, 0xC9, 0x48, 0x0F, 0x45, 0xC2};
        const std::array<std::uint8_t, 3> leaR8 = {0x4C, 0x8D, 0x05};

        std::memcpy(block.data(), settingsLoad.data(), settingsLoad.size());
        Put(block, 3, settingsOffset);
        if (immediateCompare) {
            block[7] = 0x80;
            block[8] = 0xB9;
            Put(block, 9, flagOffset);
            block[13] = 0;
        }
        else {
            std::memcpy(block.data() + 7, registerCompare.data(), registerCompare.size());
            Put(block, 10, flagOffset);
        }
        std::memcpy(block.data() + 14, setAndStore.data(), setAndStore.size());
        Put(block, 19, flagOffset);
        std::memcpy(block.data() + 23, settingsReload.data(), settingsReload.size());
        Put(block, 26, settingsOffset);
        std::memcpy(block.data() + 30, byteLoad.data(), byteLoad.size());
        Put(block, 33, flagOffset);
        std::memcpy(block.data() + 37, leaRdx.data(), leaRdx.size());
        std::memcpy(block.data() + 44, leaRax.data(), leaRax.size());
        std::memcpy(block.data() + 51, select.data(), select.size());
        std::memcpy(block.data() + 57, leaR8.data(), leaR8.size());
        std::memcpy(block.data() + 64, leaRdx.data(), leaRdx.size());

        const auto enabledDisplacement = static_cast<std::int32_t>(
            static_cast<std::int64_t>(enabledRva) - (rva + 57) - 7);
        const auto disabledDisplacement = static_cast<std::int32_t>(
            static_cast<std::int64_t>(disabledRva) - (rva + 64) - 7);
        Put(block, 60, enabledDisplacement);
        Put(block, 67, disabledDisplacement);
        PutBytes(bytes, Raw(rva), block);
    }

    std::vector<std::uint8_t> MakeValidFixture(bool legacy = false)
    {
        std::vector<std::uint8_t> bytes(0x8400, 0xCC);
        Put(bytes, 0x00, std::uint16_t{0x5A4D});
        Put(bytes, 0x3C, std::uint32_t{0x80});
        Put(bytes, 0x80, std::uint32_t{0x00004550});
        Put(bytes, 0x84, std::uint16_t{0x8664});
        Put(bytes, 0x86, std::uint16_t{2});
        Put(bytes, 0x94, std::uint16_t{0xF0});

        const std::size_t optional = 0x98;
        Put(bytes, optional, std::uint16_t{0x020B});
        Put(bytes, optional + 56, std::uint32_t{0x10000});
        Put(bytes, optional + 60, std::uint32_t{0x400});
        Put(bytes, optional + 108, std::uint32_t{16});
        Put(bytes, optional + 112 + 3 * 8, std::uint32_t{0x8000});
        Put(bytes, optional + 112 + 3 * 8 + 4, std::uint32_t{24});

        const std::size_t sections = optional + 0xF0;
        std::memcpy(bytes.data() + sections, ".text", 5);
        Put(bytes, sections + 8, std::uint32_t{0x5000});
        Put(bytes, sections + 12, kTextRva);
        Put(bytes, sections + 16, std::uint32_t{0x5000});
        Put(bytes, sections + 20, kTextRaw);
        Put(bytes, sections + 36, std::uint32_t{0x60000020});

        const std::size_t rdata = sections + 40;
        std::memcpy(bytes.data() + rdata, ".rdata", 6);
        Put(bytes, rdata + 8, std::uint32_t{0x3000});
        Put(bytes, rdata + 12, kRdataRva);
        Put(bytes, rdata + 16, std::uint32_t{0x3000});
        Put(bytes, rdata + 20, kRdataRaw);
        Put(bytes, rdata + 36, std::uint32_t{0x40000040});

        const std::array<std::uint8_t, 15> hookPrefix = {
            0x48, 0x89, 0x5C, 0x24, 0x08,
            0x48, 0x89, 0x74, 0x24, 0x10,
            0x48, 0x89, 0x7C, 0x24, 0x18};
        PutBytes(bytes, Raw(0x1000), hookPrefix);

        constexpr std::uint32_t taaAction = 0x6000;
        constexpr std::uint32_t sharpenAction = 0x6100;
        constexpr std::uint32_t taaEnabled = 0x6200;
        constexpr std::uint32_t taaDisabled = 0x6300;
        constexpr std::uint32_t sharpenEnabled = 0x6400;
        constexpr std::uint32_t sharpenDisabled = 0x6500;
        PutString(bytes, taaAction,
            "PearlAbyssEngine.Debug.ToggleRenderingFeature.TemporalAA");
        PutString(bytes, sharpenAction,
            "PearlAbyssEngine.Debug.ToggleRenderingFeature.PostProcessSharpen");
        PutString(bytes, taaEnabled, "Temporal AA is enabled");
        PutString(bytes, taaDisabled, "Temporal AA is disabled");
        PutString(bytes, sharpenEnabled, "Post Process Sharpen is enabled");
        PutString(bytes, sharpenDisabled, "Post Process Sharpen is disabled");

        PutRipLea(bytes, 0x1080, {0x48, 0x8D, 0x15}, taaAction);
        PutRipLea(bytes, 0x1087, {0x48, 0x8D, 0x0D}, 0x3000);
        PutRipLea(bytes, 0x1100, {0x48, 0x8D, 0x15}, sharpenAction);
        PutRipLea(bytes, 0x1107, {0x48, 0x8D, 0x0D}, 0x3100);
        if (legacy) {
            PutLegacyWrapper(bytes, 0x3000, 0x5A);
            PutLegacyWrapper(bytes, 0x3100, 0x5E);
            PutToggle(bytes, 0x2100, 0x15E, taaEnabled, taaDisabled, true, 0x590);
            PutToggle(bytes, 0x2200, 0x166, sharpenEnabled, sharpenDisabled, true, 0x590);
        }
        else {
            PutCompactWrapper(bytes, 0x3000, 0x5A);
            PutCompactWrapper(bytes, 0x3100, 0x61);
            PutToggle(bytes, 0x2100, 0x162, taaEnabled, taaDisabled, false, 0x5A0);
            PutToggle(bytes, 0x2200, 0x16A, sharpenEnabled, sharpenDisabled, false, 0x5A0);
        }

        Put(bytes, Raw(0x8000), std::uint32_t{0x1000});
        Put(bytes, Raw(0x8000) + 4, std::uint32_t{0x1300});
        Put(bytes, Raw(0x8000) + 8, std::uint32_t{0x8050});
        Put(bytes, Raw(0x8000) + 12, std::uint32_t{0x2000});
        Put(bytes, Raw(0x8000) + 16, std::uint32_t{0x2800});
        Put(bytes, Raw(0x8000) + 20, std::uint32_t{0x8060});
        return bytes;
    }
}

int main()
{
    {
        const auto fixture = MakeValidFixture();
        const ftaa::OfflineScanResult result = ftaa::ScanCrimsonDesertImage(fixture);
        if (!result.success) {
            for (const std::string& diagnostic : result.diagnostics) {
                std::cerr << diagnostic << '\n';
            }
        }
        assert(result.success);
        assert(result.profile.imageSize == 0x10000);
        assert(result.profile.registrationRva == 0x1000);
        assert(result.profile.switchHandlerRva == 0x2000);
        assert(result.profile.taaWrapperRva == 0x3000);
        assert(result.profile.sharpenWrapperRva == 0x3100);
        assert(result.profile.rendererAccessMode ==
               ftaa::ProfileRendererAccessMode::DirectOwnerPointer);
        assert(result.profile.actionOwnerOffset == 0x30);
        assert(result.profile.rendererPointerOffset == 0x58);
        assert(result.profile.switchHandlerVtableOffset == 0xA0);
        assert(result.profile.settingsPointerOffset == 0x5A0);
        assert(result.profile.temporalAaFlagOffset == 0x162);
        assert(result.profile.postProcessSharpenFlagOffset == 0x16A);
        assert(result.profile.taaActionId == 0x5A);
        assert(result.profile.sharpenActionId == 0x61);
    }

    {
        auto duplicateString = MakeValidFixture();
        PutString(
            duplicateString,
            0x6700,
            "PearlAbyssEngine.Debug.ToggleRenderingFeature.TemporalAA");
        assert(!ftaa::ScanCrimsonDesertImage(duplicateString).success);
    }

    {
        auto changedHook = MakeValidFixture();
        changedHook[Raw(0x1000)] = 0x90;
        assert(!ftaa::ScanCrimsonDesertImage(changedHook).success);
    }

    {
        const auto legacyFixture = MakeValidFixture(true);
        const ftaa::OfflineScanResult result =
            ftaa::ScanCrimsonDesertImage(legacyFixture);
        assert(result.success);
        assert(result.profile.rendererAccessMode ==
               ftaa::ProfileRendererAccessMode::VirtualGetter);
        assert(result.profile.actionOwnerOffset == 0x30);
        assert(result.profile.getRendererVtableOffset == 0x48);
        assert(result.profile.rendererPointerOffset == 0);
        assert(result.profile.settingsPointerOffset == 0x590);
        assert(result.profile.temporalAaFlagOffset == 0x15E);
        assert(result.profile.postProcessSharpenFlagOffset == 0x166);
    }

    std::cout << "OfflinePeScanner tests passed\n";
    return 0;
}
