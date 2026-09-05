# Nexus Mods review notes

## Scope and source map

This repository contains the v0.4.0 companion updater source and its embedded
ASI source. It is not a malware certification or an assertion that Nexus has
approved the files. The quarantine message alone does not identify its cause.

| Component | Source | Purpose |
| --- | --- | --- |
| Installer and CLI | `updater/CrimsonDesertFTAAUpdater.cpp` | Reads game PE, validates bundled ASI, stages installation, backups, profile and logs |
| Offline discovery | `updater/OfflinePeScanner.cpp` | Checks PE structures and recognized renderer instruction families |
| Embedded ASI validation | `updater/CompanionAsiValidator.cpp` | Parses compatibility export from ASI bytes without loading it |
| Runtime entry point | `companion/CrimsonDesertTAACompanion.cpp` | Validates sidecar and independently rescans before activating |
| Shared runtime implementation | `src/CrimsonDesertTAA.cpp` | Included by companion source; renderer discovery, hook and settings writes |
| File and export contracts | `src/ProfileFormat.h`, `src/CompanionContract.h` | Versioned structures |
| Build and embedding | `companion/CMakeLists.txt`, `companion/GenerateEmbeddedAsiResource.cmake`, `companion/CrimsonDesertFTAA.def` | Compiles DLL/ASI, exports contract, embeds result as updater resource |
| Regression fixtures | `tests/*.cpp` | Synthetic scanner and ASI-validation tests |

The historical `src/CrimsonDesertTAA.cpp` is an active build dependency even
though the companion wrapper replaces its entry-point names. Do not omit it.

## Intended operations

The updater opens `CrimsonDesert.exe` read-only, calculates its SHA-256, and
requires a unique internally consistent scanner result. It uses the already
compiled ASI resource; it does not compile code on the user's computer, patch
an arbitrary old ASI, or download a release. It parses the embedded DLL without
loading/executing that DLL in the updater process.

The supplied updater source has no network-download, telemetry, service,
scheduled-task, or startup-registration implementation. This describes the
source reviewed here, not an independently verified quarantined binary.

## Writes and recovery

- Installs `CrimsonDesertFTAA.asi` and replaces the generated
  `CrimsonDesertFTAA.profile` next to the game executable.
- Uses temporary staging files in the target directory, flushes staged data,
  and cleans up/attempts rollback on failure.
- Moves existing `CrimsonDesertFTAA.asi` and legacy `CrimsonDesertTAA.asi`, when
  needed, to unused `.disabled-backup`, `.disabled-backup.1`, etc. names.
  An identical current ASI is left in place. Recovery can itself fail due to
  filesystem errors; consult the log rather than assuming rollback succeeded.
- Writes `CrimsonDesertFTAA-Updater.log` beside the updater. Scan-only and
  embedded-validation modes also write this log; they are not zero-write modes.
- The running ASI writes `CrimsonDesertFTAA.log` and normally resets it for
  each launch. Logs may contain local paths; redact private path details before
  posting them publicly.

The updater does not alter the game executable or game archives on disk.
The ASI is loaded into the game by a separate ASI loader. After validation it
uses a registration hook/trampoline and changes native TAA and sharpening
Boolean settings in game memory. Shared runtime code uses `VirtualAlloc`,
`VirtualProtect`, and a worker thread for those operations. Review these paths
explicitly; “read-only game scan” must not be mistaken for “no memory changes.”

## Fail-closed checks and limits

Missing/ambiguous scanner landmarks reject installation. At runtime the ASI
checks the profile's executable identity, field ranges and digest, independently
rediscovers the renderer values, and requires agreement before hooking. The
profile digest is a corruption check, not a signature or trust boundary.
Supported scanner instruction families are documented in `COMPANION_UPDATER.md`.
These safeguards do not guarantee all future builds are supported or bug-free.

## Suggested review sequence

1. Establish that the source commit corresponds to the submitted executable.
2. Follow `../BUILDING.md`, including Debug regression tests and the resource
   self-test. Neither step requires the game.
3. Review PE parsing, file replacement, runtime memory writes and failure paths.
4. If game testing is required, use a backed-up test installation and retain
   logs. `--scan-only --no-pause` scans without ASI/profile installation.
5. Record actual results and any scanner findings. Do not disable or bypass
   antivirus or Nexus quarantine checks to distribute the file.

The uploader must provide the exact quarantined file link, source commit link,
and actual binary/archive hashes. Review and approval remain Nexus's decision.
