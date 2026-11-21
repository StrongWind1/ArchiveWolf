# Security Policy

## Reporting a vulnerability

Please report security vulnerabilities privately. **Do not open a public issue.**

Use GitHub's private vulnerability reporting: open the **Security** tab on the [repository](https://github.com/StrongWind1/ArchiveWolf/security/advisories) and choose **Report a vulnerability**.

Include:

- A description of the vulnerability and its impact.
- Steps to reproduce: the command line, and the archive that triggers it.
- The commit the binary was built from (`git rev-parse HEAD`), the output of `archivewolf --version`, and your environment.

You can expect an initial acknowledgement within a few days. Once the issue is confirmed and a fix is available, we will coordinate a disclosure timeline with you.

## Supported versions

There is no release yet: ArchiveWolf is built from source. Security fixes go to the `main` branch. Please reproduce the issue on the current `main` before reporting.

## Scope

ArchiveWolf reads archives that may be built to break it. These are vulnerabilities in the tool, in any of its commands:

- A crash or a hang on any file, or memory or time beyond the limits the tool states. The README lists them under [Handling untrusted archives](README.md#handling-untrusted-archives): for `info` and `hash`, memory grows with the headers of an archive and not with its size, and `attack rar-13` holds an archive of 1 GiB at most.
- Text from an archive (a name, a comment, a path) that acts on the terminal or forges a line of output.
- A file that is written or changed anywhere but where the tool says it writes: the files that `-o` and `--state` name, and the speed measurement that `attack zip-crypto` keeps in its cache folder. Also a file at a path of `-o` or `--state` that is overwritten, and another program that is started.

A hash line that no password can confirm is a defect and is welcome as an ordinary issue, not as a vulnerability.

ArchiveWolf is security-research tooling intended for authorized testing only. Reports demonstrating misuse against third-party systems are out of scope.

Hash lines contain encrypted archive data (ciphertext, salts, vectors, check values). Handle them with the same care as the archive they come from.
