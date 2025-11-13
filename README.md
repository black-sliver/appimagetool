# appimagetool rehost

This repository is currently rehosting the releases from
[AppImage/appimagetool](https://github.com/AppImage/appimagetool)
to allow reproducible builds, provide some level of traceability and mitigate potential supply chain attacks.

The original release artifacts on AppImage/appimagetool are not tagged, not signed and not attested.

How a rehost release is created:
* Check code changes.
* Compare upstream action artifacts to release artifacts (currently done by hand).
* Check that all upstream commits and no extra commits are merged here to retain the actual source.
* The rehost action is started by pushing a tag, downloads the latest upstream release, uses actions/attest and creates
  an [immutable release](https://github.blog/changelog/2025-08-26-releases-now-support-immutability-in-public-preview/).

The attestation can be checked and reviewed using
Actions -> Attestations,
[gh attestation verify](https://cli.github.com/manual/gh_attestation_verify),
[rekor search](https://search.sigstore.dev/) with the hash
and/or `cosign verify-blob` with `--bundle`, `--certificate-identity`
and `--certificate-oidc-issuer https://token.actions.githubusercontent.com`

Note that this only attests when and how it was downloaded, not what went into it. The build itself is not fully
reproducible.

There is currently no signature to check. The appimagetool AppImage is not signed.

Once validated, you can simply use the tag and check the SHA256 to verify the download.

Original README follows:

# appimagetool

## Usage

`appimagetool` is used to generate an AppImage from an existing `AppDir`. Many community-provided higher-level [tools for deploying applications in AppImage format](https://github.com/AppImageCommunity/awesome-appimage/blob/main/README.md#appimage-developer-tools) use it internally. A precompiled version can be downloaded on [GitHub Releases](../..//releases), but in most cases you will be better off using one of the higher-level tools instead of using `appimagetool` directly.

Usage in a nutshell, assuming that you already have an [AppDir](https://github.com/AppImage/AppImageSpec/blob/master/draft.md#appdir) in place:

```
ARCH=x86_64 ./appimagetool-x86_64.AppImage some.AppDir
```

Detailed usage:
```
Usage:
  appimagetool [OPTION...] SOURCE [DESTINATION] - Generate AppImages from existing AppDirs

Help Options:
  -h, --help                  Show help options

Application Options:
  -l, --list                  List files in SOURCE AppImage
  -u, --updateinformation     Embed update information STRING; if zsyncmake is installed, generate zsync file
  -g, --guess                 Guess update information based on environment variables set by common CI systems (GitHub actions, GitLab CI)
  --version                   Show version number
  -v, --verbose               Produce verbose output
  -s, --sign                  Sign with gpg[2]
  --comp                      Squashfs compression
  -n, --no-appstream          Do not check AppStream metadata
  --exclude-file              Uses given file as exclude file for mksquashfs, in addition to .appimageignore.
  --runtime-file              Runtime file to use
  --sign-key                  Key ID to use for gpg[2] signatures
  --sign-args                 Extra arguments to use when signing with gpg[2]
```

### Environment variables

Some of the parameters above can alternatively be specified as environment variables. Also, some additional environment variables are available, too.

- `ARCH`: Needs to be set whenever appimagetool cannot automatically determine the architecture of the binaries inside the AppDir to choose a suitable runtime (e.g., when binaries for multiple architectures or just shell scripts are contained in there).
- `APPIMAGETOOL_APP_NAME`: If no destination is set by the user, appimagetool automatically generates a suitable output filename, using the root desktop entry's `Name` field. With this environment variable, this value can be set explicitly by the user.
- `APPIMAGETOOL_SIGN_PASSPHRASE`: If the `--sign-key` is encrypted and requires a passphrase to be used for signing (and, for some reason, GnuPG cannot be used interactively, e.g., in a CI environment), this environment variable can be used to safely pass the key.
- `VERSION`: This value will be inserted by appimagetool into the root desktop file and (if the destination parameter is not provided by the user) in the output filename.

## Building

To build for various architectures on a local machine (or on GitHub Codespaces) using Docker:

* For 64 bit Intel, run `ARCH=x86_64 bash ./ci/build-in-docker.sh`
* For 32 bit Intel, run `ARCH=i686 bash ./ci/build-in-docker.sh`

If you are on an Intel machine and would like to cross-compile for ARM:

* Prepare the Docker system for cross-compiling with `docker run --rm --privileged multiarch/qemu-user-static --reset -p yes`, then run
* For 64 bit ARM, run `ARCH=aarch64 bash ./ci/build-in-docker.sh`
* For 32 bit ARM, run `ARCH=armhf bash ./ci/build-in-docker.sh`

## Changelog

* Unlike previous versions of this tool provided in the [AppImageKit](https://github.com/AppImage/AppImageKit/) repository, this version downloads the latest AppImage runtime (which will become part of the AppImage) from https://github.com/AppImage/type2-runtime/releases. If you do not like this (or if your build system does not have Internet access), you can supply a locally downloaded AppImage runtime using the `--runtime-file` parameter instead.
