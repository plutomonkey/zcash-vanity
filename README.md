Zcash Vanity Address Generator
==============================

> I just thought of something.  Eventually there'll be some interest in brute force scanning bitcoin addresses to find one with the first few characters customized to your name, kind of like getting a phone number that spells out something.  Just by chance I have my initials.

*—Satoshi Nakamoto in an email to Hal Finney in 2009, referring to his Bitcoin address 1NSwywA5Dvuyw89sfs3oLPvLiDNGf48cPD.*

Zcash-vanity is a high-throughput vanity address generator for [Zcash](https://z.cash) shielded addresses (z-addrs), i.e. those starting with "zc".

You can search for addresses with particular prefixes, e.g. "zcVANiTY".  The engine is written in OpenCL so that it can run on devices such as GPUs.  Currently, NVIDIA's GTX 1080 Ti can locate an exact 6-character prefix (excluding "zc") in around 30 seconds.

Case-insensitive matching and multiple prefixes are also supported.

## Installation

The engine wrapper is written in Rust.  At the moment, the easiest way to install zcash-vanity is to install [Rust](https://www.rust-lang.org), which comes with a package manager called Cargo. Then run:

    cargo install zcash-vanity

This should download all dependencies, build and add `zcash-vanity` to your path.  You will also need OpenCL installed.

## Usage

**Note:** not all 58 characters can be used as the third character of the prefix; only the following may be used: `[8-9,A-Z,a-h]`.

The following should list all available options:

    zcash-vanity --help

Note that unless otherwise specified, all available OpenCL devices are used, which may include your CPU on some platforms.

## Related Work

* [zcash-mini](https://github.com/FiloSottile/zcash-mini), a portable wallet generator written in Go by [Filippo Valsorda](https://blog.filippo.io/hi/), which supports vanity address generation (z-addrs) too but not using the GPU.
* [vanitygen_z](https://github.com/exploitagency/vanitygen_z), a modified version of Bitcoin's vanitygen, for generating transparent Zcash addresses (t-addrs) using OpenCL.

Donations gratefully received at [zcVANiTYZ1VxZp9dr6CEqfesYyfak8d6ZDFh4LLQPtHdGUb47CkpHzspFg4YV4NqsfyWkUxs4rcrzhKGsqHhXkzZsWkDaLT](zcash:zcVANiTYZ1VxZp9dr6CEqfesYyfak8d6ZDFh4LLQPtHdGUb47CkpHzspFg4YV4NqsfyWkUxs4rcrzhKGsqHhXkzZsWkDaLT).

Please see <https://zcash.plutomonkey.com/vanity/> for further information and new releases.
