# Review-package status

Prepared: 2026-09-05.

## Source provenance

Based on `CrimsonDesert-FTAA-v0.4.0-self-contained-updater-source-test.zip`.
All original source, tests, build scripts, documentation and license files are
preserved byte-for-byte. Only supplemental repository/reviewer files were added.
`ORIGINAL_SOURCE_SHA256.txt` records the hashes of those original files.

## Checks performed for this package

- Both portable C++20 test suites compiled with GCC, warnings enabled, without
  `NDEBUG`, and ran successfully against synthetic fixtures.
- Original-file byte comparison and final archive integrity were checked.
- Build inputs, embedding configuration, file-write behavior and runtime
  entry-point relationships were inspected to prepare the reviewer notes.

## Not established here

- A Windows MSVC build or execution of the finished Windows self-test.
- A new in-game test, installer rollback test, or current-game compatibility test.
- VirusTotal results, antivirus clearance, or Nexus approval.
- A match between this source and the exact quarantined `.exe` (not supplied).
- Reproducible, byte-identical Windows release builds.

The earlier source-test documentation is retained as historical documentation;
its release checklist must not be interpreted as already completed.

Review information
Source repository: https://github.com/AckM3/CrimsonDesertFTAA-Updater
Source package used: CrimsonDesert-FTAA-GitHub-review-package.zip
Nexus quarantined file ID: 7913004
Nexus file title: CrimsonDesertFTAA Updater
Filename: CrimsonDesertFTAA-Updater.exe
Quarantined updater SHA-256: 7273743E25FCBD07A96EFB7C9E08761F3FE8445E102F4374719AB5F469E34039
Original build environment and configuration: Built on Windows from the source package listed above. Exact compiler, Windows SDK, CMake versions, and build configuration pending confirmation.
Windows test results and sanitized logs: Compilation completed successfully, as reported by the author. Runtime test results and sanitized logs pending.

