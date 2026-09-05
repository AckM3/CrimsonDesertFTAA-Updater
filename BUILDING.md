# Building and testing

## Required Windows build environment

- Windows x64.
- Visual Studio 2022 or its Build Tools, with **Desktop development with C++**.
- MSVC v143 x64/x86 tools and a Windows SDK (including the resource compiler).
- CMake 3.21 or newer, including support for the Visual Studio 2022 generator.
- Windows PowerShell for the existing convenience script.

No game executable, ASI loader, Python, npm, or third-party C++ library is needed
to compile this project or run its synthetic tests. Windows SDK `bcrypt` is
linked for hashing. Game files are needed only for game scanning/in-game tests.

## Existing release build script

Open PowerShell in the repository root after inspecting the source and script:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\build-companion.ps1
```

The execution-policy argument applies to this process; do not change a managed
policy or disable security protection to run it. If script execution is blocked,
use the explicit CMake commands below where permitted.

The script compiles the ASI first, embeds it as a resource in the updater,
runs the two test executables, runs the embedded-resource self-test, and prints
SHA-256 values. Outputs:

- `build-companion\Release\CrimsonDesertFTAA-Updater.exe`
- `build-companion\Release\CrimsonDesertFTAA.asi`

Important: the test sources use `assert`. A default Release build defines
`NDEBUG`, disabling assertions. Run the Debug tests below as well; a Release
test's success message alone is not sufficient evidence of regression coverage.

## Explicit reviewer build (assertion-enabled tests plus Release outputs)

Use a Visual Studio 2022 developer command prompt with CMake available, from
the repository root. Run each command separately and stop if it fails:

```bat
cmake -S companion -B build-review -G "Visual Studio 17 2022" -A x64 -DFTAA_BUILD_TESTS=ON
cmake --build build-review --config Debug
ctest --test-dir build-review -C Debug --output-on-failure
build-review\Debug\CrimsonDesertFTAA-Updater.exe --verify-embedded --no-pause
cmake --build build-review --config Release
build-review\Release\CrimsonDesertFTAA-Updater.exe --verify-embedded --no-pause
```

The Release updater and ASI are in `build-review\Release`. The self-test does
not need the game and does not install an ASI, but writes an updater log.
The CMake source directory is `companion`, not the repository root.

The original `companion/CMakeLists.txt` is the build authority. Its ASI target
uses `/guard:cf-`; this setting is preserved, not silently changed for review.
There are no download steps in this CMake project.

## Portable tests (Linux/GCC, not a Windows release build)

From the repository root, with a C++20-capable GCC:

```sh
g++ -std=c++20 -Wall -Wextra -pedantic -I updater -I src updater/OfflinePeScanner.cpp tests/OfflinePeScannerTests.cpp -o /tmp/ftaa-scanner-tests
/tmp/ftaa-scanner-tests
g++ -std=c++20 -Wall -Wextra -pedantic -I updater -I src updater/CompanionAsiValidator.cpp tests/CompanionAsiValidatorTests.cpp -o /tmp/ftaa-validator-tests
/tmp/ftaa-validator-tests
```

Do not add `-DNDEBUG`. These tests use synthetic byte fixtures and do not launch
or modify a game. Passing them does not validate the Windows installer or hooks.

## Identify the exact Nexus release

Hash the actual quarantined executable and archive, not only a new rebuild.
For each actual path in PowerShell:

```powershell
Get-FileHash -LiteralPath 'C:\path\to\CrimsonDesertFTAA-Updater.exe' -Algorithm SHA256
Get-FileHash -LiteralPath 'C:\path\to\uploaded-release.zip' -Algorithm SHA256
```

Record the source commit, MSVC/CMake/SDK versions, build configuration, release
filename and hashes in the review request. Preserve the original binaries.
This project does not promise byte-identical rebuilds: tool versions, paths,
and PE timestamps can change output hashes. A matching version label alone
does not establish source-to-binary correspondence. If the source used for the
quarantined file differs, publish that exact source instead.
