# Crimson Desert FTAA — Companion Updater 1.0.0

Scans your installed Crimson Desert executable, installs its bundled FTAA ASI,
and generates the matching compatibility profile when the required renderer
structure passes validation. The companion mod disables native TAA and
post-process sharpening.

This is an offline tool: it does not fetch newer releases from GitHub or Nexus.
A major renderer change can require an updated scanner and updater.

## AI development disclosure

Although I come from a technical background, I am not skilled enough to make
something like this on my own. However, TAA’s ghosting tends to give me very bad
motion sickness, and I find it to be an overall poor implementation of
anti-aliasing. This mod was developed almost entirely using AI. Feel free to
modify, improve, update, or redistribute it without restriction.

## For Nexus reviewers

- [Build instructions and dependencies](BUILDING.md)
- [Behavior, file access, and review map](docs/NEXUS_REVIEW.md)
- [Verification status and release identity](PROJECT_STATUS.md)
- [Original technical documentation](docs/COMPANION_UPDATER.md)
- [Release checklist](RELEASE_CHECKLIST.md)

This package preserves all 19 files from
`CrimsonDesert-FTAA-v0.4.0-self-contained-updater-source-test.zip` unchanged.
Additional files provide submission documentation. The exact quarantined
executable has not been supplied for comparison; its correspondence with this
source must be established by the uploader before submitting the review.

## Requirements and use

Windows x64, the Steam version of Crimson Desert, and a separately installed
x64 ASI loader are required for in-game use. Build tools are needed only to
compile the source, not to run the updater. Visual Studio Code is not required.
The source uses the normal MSVC runtime configuration; “self-contained” refers
to the embedded ASI, not a guarantee of no Windows runtime prerequisites.

1. Close the game and preserve your working mod files.
2. Place `CrimsonDesertFTAA-Updater.exe` beside `CrimsonDesert.exe` in `bin64`.
3. Run it and check for success. It creates `CrimsonDesertFTAA.asi` and
   `CrimsonDesertFTAA.profile`, and writes an updater log beside the updater.
4. Launch the game and inspect `CrimsonDesertFTAA.log` for runtime validation.

The ASI built by this companion project requires its generated profile; it is
not a drop-in equivalent of an older standalone ASI release.

Existing FTAA ASIs are preserved under unique `.disabled-backup` names when
replacement is needed. Do not rename those backups while another FTAA ASI is
active. The game executable is read, not modified on disk. The ASI does modify
the running game's memory after validation; see the reviewer notes.

The scanner recognizes specific instruction families, not all possible future
game versions. Stop on validation failure; there is no force/bypass option.

## License and third-party components

The original [CC0 dedication](LICENSE) is retained. Game files, game assets,
Microsoft tools, and an ASI loader are not included or covered by that notice.
Obtain the loader separately from the
[Ultimate ASI Loader project](https://github.com/ThirteenAG/Ultimate-ASI-Loader).


