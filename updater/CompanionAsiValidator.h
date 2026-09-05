#pragma once

#include "CompanionContract.h"

#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace ftaa
{
    struct CompanionAsiValidationResult
    {
        bool success = false;
        CompanionContractV1 contract{};
        std::vector<std::string> diagnostics;
    };

    // Parses the ASI as a file-backed AMD64 PE32+ DLL. It does not load or
    // execute the module. Success requires one correctly named exported data
    // record with the profile-reader and independent-rescan capabilities.
    CompanionAsiValidationResult ValidateCompanionAsi(
        std::span<const std::uint8_t> fileBytes);
}
