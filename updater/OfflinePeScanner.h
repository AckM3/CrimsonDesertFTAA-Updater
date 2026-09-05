#pragma once

#include "ProfileFormat.h"

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace ftaa
{
    struct OfflineProfile
    {
        ProfileRendererAccessMode rendererAccessMode =
            ProfileRendererAccessMode::VirtualGetter;
        std::uint32_t imageSize = 0;
        std::uint64_t registrationRva = 0;
        std::uint64_t switchHandlerRva = 0;
        std::uint64_t taaWrapperRva = 0;
        std::uint64_t sharpenWrapperRva = 0;
        std::uint32_t actionOwnerOffset = 0;
        std::uint32_t getRendererVtableOffset = 0;
        std::uint32_t rendererPointerOffset = 0;
        std::uint32_t switchHandlerVtableOffset = 0;
        std::uint32_t settingsPointerOffset = 0;
        std::uint32_t temporalAaFlagOffset = 0;
        std::uint32_t postProcessSharpenFlagOffset = 0;
        std::uint8_t taaActionId = 0;
        std::uint8_t sharpenActionId = 0;
    };

    struct OfflineScanResult
    {
        bool success = false;
        OfflineProfile profile{};
        std::vector<std::string> diagnostics;
    };

    // Reads only the supplied bytes. It never opens or modifies a file.
    OfflineScanResult ScanCrimsonDesertImage(std::span<const std::uint8_t> image);
}
