cmake_minimum_required(VERSION 3.21)

project(CrimsonDesertFTAACompanion VERSION 0.4.0 LANGUAGES CXX)

if(NOT WIN32 OR NOT MSVC)
    message(FATAL_ERROR "Build with 64-bit Microsoft Visual C++ on Windows.")
endif()
if(NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
    message(FATAL_ERROR "The FTAA mod and updater must be built for x64.")
endif()
enable_language(RC)

add_library(CrimsonDesertFTAA SHARED
    CrimsonDesertTAACompanion.cpp
    CrimsonDesertFTAA.def
    ../src/CompanionContract.h
    ../src/ProfileFormat.h
)
target_compile_features(CrimsonDesertFTAA PRIVATE cxx_std_20)
target_compile_definitions(CrimsonDesertFTAA PRIVATE
    UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX
)
target_compile_options(CrimsonDesertFTAA PRIVATE
    /W4 /permissive- /EHsc /guard:cf-
)
target_link_libraries(CrimsonDesertFTAA PRIVATE bcrypt)
set_target_properties(CrimsonDesertFTAA PROPERTIES
    PREFIX ""
    OUTPUT_NAME "CrimsonDesertFTAA"
    SUFFIX ".asi"
)

set(
    FTAA_EMBEDDED_ASI_RESOURCE
    "${CMAKE_CURRENT_BINARY_DIR}/$<CONFIG>/EmbeddedCompanionAsi.rc"
)
add_custom_command(
    OUTPUT "${FTAA_EMBEDDED_ASI_RESOURCE}"
    COMMAND
        "${CMAKE_COMMAND}"
        "-DINPUT=$<TARGET_FILE:CrimsonDesertFTAA>"
        "-DOUTPUT=${FTAA_EMBEDDED_ASI_RESOURCE}"
        -P "${CMAKE_CURRENT_SOURCE_DIR}/GenerateEmbeddedAsiResource.cmake"
    DEPENDS
        CrimsonDesertFTAA
        "${CMAKE_CURRENT_SOURCE_DIR}/GenerateEmbeddedAsiResource.cmake"
    COMMENT "Embedding the matching CrimsonDesertFTAA.asi in the updater"
    VERBATIM
)
add_library(FTAAOfflineScanner STATIC
    ../updater/CompanionAsiValidator.cpp
    ../updater/CompanionAsiValidator.h
    ../updater/OfflinePeScanner.cpp
    ../updater/OfflinePeScanner.h
    ../src/CompanionContract.h
    ../src/ProfileFormat.h
)
target_compile_features(FTAAOfflineScanner PRIVATE cxx_std_20)
target_include_directories(FTAAOfflineScanner PUBLIC ../src ../updater)
target_compile_options(FTAAOfflineScanner PRIVATE /W4 /permissive- /EHsc)

add_executable(CrimsonDesertFTAAUpdater
    ../updater/CrimsonDesertFTAAUpdater.cpp
    "${FTAA_EMBEDDED_ASI_RESOURCE}"
)
add_dependencies(CrimsonDesertFTAAUpdater CrimsonDesertFTAA)
target_compile_features(CrimsonDesertFTAAUpdater PRIVATE cxx_std_20)
target_include_directories(CrimsonDesertFTAAUpdater PRIVATE ../src ../updater)
target_compile_definitions(CrimsonDesertFTAAUpdater PRIVATE
    UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX
)
target_compile_options(CrimsonDesertFTAAUpdater PRIVATE /W4 /permissive- /EHsc)
target_link_libraries(CrimsonDesertFTAAUpdater PRIVATE FTAAOfflineScanner bcrypt)
set_target_properties(CrimsonDesertFTAAUpdater PROPERTIES
    OUTPUT_NAME "CrimsonDesertFTAA-Updater"
)

option(FTAA_BUILD_TESTS "Build offline-scanner regression tests" ON)
if(FTAA_BUILD_TESTS)
    enable_testing()
    add_executable(FTAAOfflineScannerTests ../tests/OfflinePeScannerTests.cpp)
    target_compile_features(FTAAOfflineScannerTests PRIVATE cxx_std_20)
    target_compile_options(FTAAOfflineScannerTests PRIVATE /W4 /permissive- /EHsc)
    target_link_libraries(FTAAOfflineScannerTests PRIVATE FTAAOfflineScanner)
    add_test(NAME FTAAOfflineScannerTests COMMAND FTAAOfflineScannerTests)

    add_executable(
        FTAACompanionAsiValidatorTests
        ../tests/CompanionAsiValidatorTests.cpp
    )
    target_compile_features(FTAACompanionAsiValidatorTests PRIVATE cxx_std_20)
    target_compile_options(
        FTAACompanionAsiValidatorTests PRIVATE /W4 /permissive- /EHsc
    )
    target_link_libraries(FTAACompanionAsiValidatorTests PRIVATE FTAAOfflineScanner)
    add_test(
        NAME FTAACompanionAsiValidatorTests
        COMMAND FTAACompanionAsiValidatorTests
    )
endif()
