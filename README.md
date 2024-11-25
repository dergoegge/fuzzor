# Fuzzor

Work in progress continuous fuzzing infrastructure. Mainly build and maintained
to continuously fuzz [Bitcoin Core](https://github.com/bitcoin/bitcoin) but
support for adding and fuzzing other projects is available (see `projects/`).

## Features

- Crash deduplication
- Automatic bug reports
- Automatic coverage report creation
- Support for major fuzzing engines (AFL++, libFuzzer, honggfuzz, Native
  Golang)
- Real-time ensemble fuzzing
- Pull request fuzzing
- Coverage based harness scheduling
- Support for experimental fuzzing engines (e.g. fuzz driven characterization
  testing with [SemSan](https://github.com/dergoegge/semsan))

### Planned Features

- Snapshot fuzzing support (e.g. using full-system `libafl_qemu` and/or `nyx`)
- Concolic fuzzing engine support
- Automatic bug triaging

## Bugs discovered by Fuzzor

- [core-lightning: fuzz-bolt12-bech32-decode: index 128 out of bounds for type 'const int8_t[128]' (aka 'const signed char[128]')](https://github.com/ElementsProject/lightning/pull/7322)
- [lnd: FuzzProbability: normalization factor is zero](https://github.com/lightningnetwork/lnd/issues/9085)
- [lnd: FuzzReplyChannelRange: failed to encode message to buffer](https://github.com/lightningnetwork/lnd/pull/9084)
- [bitcoin: wallet_bdb_parser: BDB builtin encryption is not supported](https://github.com/bitcoin/bitcoin/issues/30166)
- [bitcoin #30243: mocked_descriptor_parse: Assertion '(leaf_version & ~TAPROOT_LEAF_MASK) == 0' failed](https://github.com/bitcoin/bitcoin/pull/30243#issuecomment-2169240015)
- [bitcoin: rpc: runtime error: reference binding to null pointer of type 'const value_type' (aka 'const CTxOut')](https://github.com/bitcoin/bitcoin/pull/29855)
- [bitcoin: script: Assertion '!extract_destination_ret' failed.](https://github.com/bitcoin/bitcoin/issues/30615)
- [bitcoin: scriptpubkeyman: heap-buffer-overflow miniscript.cpp in CScript BuildScript](https://github.com/bitcoin/bitcoin/issues/30864)
- [bitcoin: p2p_headers_presync: Assertion 'total_work < chainman.MinimumChainWork()' failed](https://github.com/bitcoin/bitcoin/pull/31213)
- [bitcoin: connman: terminate called after throwing an instance of 'std::bad_alloc']()
