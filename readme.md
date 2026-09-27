# Seashell Launcher

This launcher accepts the site's `seashell-player:` Play links, including the
`clientversion` values `2017L`, `2018L`, `2020L`, and `2021M`. Older links with
`clientyear` are mapped to the corresponding version. Client packages are
installed side by side under `%LOCALAPPDATA%\Seashell\Clients`; installing one
version never deletes another.

## Build and test

Run `cargo test` and `cargo build --release` on Windows. The x64 build script
is `win-build-release.bat`; Cargo builds `SeashellPlayerLauncher.exe` directly.
Opening the launcher directly registers the protocol and opens the games page.
Do not publish it to players until the manifest and matching client packages
have been checked with real game joins. The build does not use a packer or UPX.

## Security and release status

The `1.6.5` source is unreleased. Do not publish an executable from it until
the Defender review, signing, and game-join checks are complete.

The launcher accepts Play links only for the Seashell join endpoint, verifies an
Ed25519-signed manifest before downloading code, checks SHA-256 hashes, and now
requires launcher and client downloads to come directly from that manifest's
HTTPS origin (no redirects). Opening the games page uses Windows ShellExecute,
not a command interpreter. These controls reduce risk but do not make a binary
automatically safe.

The 2020 client compatibility path is an important exception: after checking
the exact client executable hash, the launcher uses Windows process-memory APIs
to replace a service domain and public join-verification key in its child
process. It does not alter the client file on disk. This behavior is visible in
`src/client_patch.rs` and must be disclosed to security reviewers. It may be
relevant to antivirus detections, but the cause has not been established.

Microsoft Defender has quarantined the unsigned 1.6.3 and 1.6.4 executables
as `Trojan:Win32/Wacatac.C!ml`; public downloads are paused pending review.
Do not bypass antivirus protection or rename/repack a binary to work around a
detection. Submit the exact flagged artifact through Microsoft's developer
sample-review process, investigate the verdict, then sign a reviewed build
with a trusted Windows publisher certificate before restoring distribution.
The signed update manifest is not a substitute for Authenticode signing.

## Client manifest

By default, the launcher reads
`https://seashell.rocks/client-downloads/manifest-v2.json`. A custom manifest URL
can be compiled in with `SEASHELL_CLIENT_MANIFEST_URL`. The endpoint must be
HTTPS and return JSON in this shape:

```json
{
  "schemaVersion": 1,
  "launcher": {
    "version": "1.6.2",
    "url": "https://seashell.rocks/client-downloads/SeashellPlayerLauncher-1.6.2.exe",
    "sha256": "<64 hexadecimal characters>"
  },
  "clients": {
    "2020L": {
      "url": "https://seashell.rocks/client-downloads/2020L-client.zip",
      "sha256": "<64 hexadecimal characters>",
      "executable": "RobloxPlayerBeta.exe"
    }
  }
}
```

The example URL and digest are placeholders, not a deployable manifest. Add
only verified client ZIPs that can join the matching server version. The 2020
Roblox executable stays byte-for-byte signed; the launcher verifies its exact
SHA-256 and substitutes only the Seashell trust-domain string in that one
running process. Other client versions are never patched by this code.
The `executable` path is relative to the ZIP's root and defaults to
`RobloxPlayerBeta.exe`. Every package requires a SHA-256 digest. The launcher
downloads, checks the digest, extracts into a staging folder, and then moves
the completed install into a version-and-digest-specific folder. If a version
is absent from the manifest, Play fails clearly instead of launching the wrong
client.

The raw UTF-8 bytes of `manifest-v2.json` must be signed with the owner's offline
Ed25519 key. Publish its 64-byte binary signature at `manifest-v2.json.sig`.
The launcher has only the public key. It refuses unsigned or changed manifests
before considering either launcher or client downloads. The private key must
never be put on the VPS, in this repository, or in a client ZIP.
The 1.6.2 manifest uses a new key and URL because the prior key is unavailable;
1.6.1 users must install 1.6.2 manually once. Future releases can auto-update
from 1.6.2 using the locally retained key. This update path is temporarily
unavailable while the affected launcher versions are withdrawn.

The optional `launcher` object makes the launcher check for newer builds on
every start. Only a numerically newer three-part version is installed. The
download must use HTTPS and match its SHA-256 digest. It is kept beside the
previous version, then started with the same Play link; the new build updates
the protocol registration after it starts. To ship a new build, publish its
immutable versioned executable first, test its hash and direct launch, then
sign and publish the manifest and signature together. Keep the previous
version available for rollback. A production Authenticode certificate would
add Windows publisher verification and reduce unsigned-app warnings.

