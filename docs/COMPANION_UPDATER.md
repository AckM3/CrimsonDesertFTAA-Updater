# 0.4.0 Self-Contained Companion Updater Test

`CrimsonDesertFTAA-Updater.exe` is a self-contained, fail-closed ASI installer
and offline profile generator. It reads the installed `CrimsonDesert.exe`,
derives the renderer landmarks used by the ASI, installs its own matching ASI,
and atomically writes `CrimsonDesertFTAA.profile` beside it. It never modifies
the game executable or game archives.

The matching ASI is embedded in the updater at build time. Before touching the
game directory, the updater validates that payload as an AMD64 PE32+ DLL and
parses its exported compatibility record. The record must explicitly advertise
the matching profile format, profile-reader support, and independent in-process
rescan. The ASI is never loaded or executed by the updater.

## Normal use

Place these files together in `Crimson Desert\bin64`:

```text
CrimsonDesertFTAA-Updater.exe
CrimsonDesert.exe
```

Close the game, double-click `CrimsonDesertFTAA-Updater.exe`, and wait for a
success message. The updater produces:

```text
CrimsonDesertFTAA.asi
CrimsonDesertFTAA.profile
CrimsonDesertFTAA-Updater.log
```

Run the updater again whenever Steam replaces `CrimsonDesert.exe`.

Command-line use is also supported:

```powershell
.\CrimsonDesertFTAA-Updater.exe "C:\Steam\steamapps\common\Crimson Desert"
.\CrimsonDesertFTAA-Updater.exe --scan-only --no-pause
.\CrimsonDesertFTAA-Updater.exe --verify-embedded --no-pause
```

`--scan-only` validates the embedded ASI and scans the game but changes no ASI
or profile. `--verify-embedded` checks only the updater's embedded ASI and is
run automatically by `build-companion.ps1`. There is no force or bypass option.

## Existing ASI versions

The updater accepts any installed FTAA ASI version by replacing it with the
embedded matching companion; it does not attempt to patch arbitrary compiled
machine code. Before replacement, exact files named `CrimsonDesertFTAA.asi` or
legacy `CrimsonDesertTAA.asi` are moved to unique `.disabled-backup`,
`.disabled-backup.1`, and later names. Those suffixes prevent ASI loaders from
loading the backups while keeping the original bytes recoverable.

The replacement ASI is first staged, flushed, and verified byte-for-byte. If an
installed ASI cannot be backed up or the replacement cannot be committed, the
updater rolls back every completed ASI move. Close the game before running it.
If the installed ASI already matches the embedded payload, it is left in place.

## Discovery gates

The updater parses the executable's PE32+ headers, section table, and x64
exception metadata. It then requires all of the following:

- Exactly one TAA action string and one post-process-sharpen action string.
- Exactly one structurally accepted callback wrapper for each action.
- One shared registration routine with the verified relocation-free hook
  prefix.
- Matching owner, renderer-access, and switch-vtable layouts in both wrappers.
- Distinct action IDs from the matching wrapper family.
- Exactly one named native Boolean-toggle block for TAA and sharpening.
- One shared switch handler and settings-pointer offset.
- Distinct, nearby one-byte Boolean field offsets.

The accepted wrapper families are the original virtual-renderer-getter layout
from game build `1.0.0.2692` and the compact direct-owner-renderer-pointer
layout observed in `1.0.0.2760`. The accepted toggle families cover the
immediate-zero and register-compare forms independently observed in those
builds. The scanner does not combine fields from different candidates.

## Profile and runtime verification

The profile is a fixed 176-byte little-endian record containing:

- Format version and enabled feature set.
- Executable file size, PE image size, and complete SHA-256.
- Registration, switch-handler, TAA-wrapper, and sharpening-wrapper RVAs.
- Renderer access mode and every relevant object/vtable/field offset.
- TAA and sharpening action IDs.
- SHA-256 over the profile body to detect truncation or corruption.

The profile digest is not treated as a trust boundary. Before the ASI uses a
profile, it verifies the executable identity, checks every value is plausible
and inside the expected executable ranges, repeats the structural scan against
the loaded image, and requires an exact field-for-field match. Only then can it
install the already-guarded registration hook. Runtime pointer, vtable-target,
and Boolean-value checks remain in place before either one-byte settings write.

## Failure behavior

If the embedded ASI self-test fails, or if a game landmark is missing,
duplicated, changed, or inconsistent, the updater returns a nonzero exit code
before changing the installed ASI or profile. The new profile is staged before
the ASI upgrade and committed only after the ASI installation succeeds. If the
profile is missing, stale, corrupt, or disagrees with the loaded executable,
the ASI remains inactive, installs no hook, and makes no renderer writes.

A larger engine or renderer rewrite can still require a new scanner build.
Automatic discovery is deliberately limited to instruction families that have
been independently observed and reviewed.

## Validation status

The portable offline scanner core has regression fixtures for:

- The compact direct-renderer wrapper plus register-compare toggle family.
- The legacy virtual-getter wrapper plus immediate-zero toggle family.
- Duplicate semantic strings.
- A changed registration hook prefix.
- A valid exported ASI companion contract.
- A legacy ASI with no companion export.
- An incompatible profile reader, missing safety capability, and x86 ASI.

The positive fixtures must resolve their complete expected data. All negative
fixtures must fail closed. A Windows MSVC x64 build and an in-game log are still
required before publishing this branch as a confirmed release. The Windows
build additionally runs the finished updater with `--verify-embedded`, which
catches a missing contract export or missing/stale ASI resource.
