# Fuzzor

Work in progress continuous fuzzing infrastructure. Mainly build and maintained
to continuously fuzz [Bitcoin Core](https://github.com/bitcoin/bitcoin) but
support for adding and fuzzing other projects is available (see `projects/`).

## Quick Start

```bash
docker build --tag fuzzor-base:latest --file infra/Dockerfile.base .

cd projects/bitcoin
docker build --tag fuzzor-bitcoin:latest .

docker run -it fuzzor-bitcoin:latest

FUZZ=txgraph ./out/libfuzzer_asan/fuzz
```

## Features

- Automatic bug reports
- Automatic coverage report creation
- Support for major fuzzing engines
  ([`AFL++`](https://github.com/AFLplusplus/AFLplusplus),
  [`libFuzzer`](https://llvm.org/docs/LibFuzzer.html),
  [`honggfuzz`](https://github.com/google/honggfuzz), [`Native
  Golang`](https://go.dev/doc/security/fuzz/))
- Crash deduplication
- Corpus minimization with all supported engines
- Real-time ensemble fuzzing
- Coverage based campaign scheduling
- Support for experimental fuzzing engines (e.g. fuzz driven characterization
  testing with [SemSan](https://github.com/dergoegge/semsan))

### Planned Features

- Support for more fuzzing engines (e.g.
  [`Radamsa`](https://gitlab.com/akihe/radamsa),
  [`libafl_libfuzzer`](https://github.com/AFLplusplus/LibAFL/tree/main/libafl_libfuzzer),
  [`libafl-fuzz`](https://github.com/AFLplusplus/LibAFL/tree/main/fuzzers/forkserver/libafl-fuzz),
  ...)
- Snapshot fuzzing support (e.g. using full-system
  [`libafl_qemu`](https://github.com/AFLplusplus/LibAFL/tree/main/libafl_qemu)
  and/or [`nyx`](https://nyx-fuzz.com/))
- Concolic fuzzing engine support
- Automatic bug triaging
- Automatic pull request fuzzing

## Bugs discovered by Fuzzor

- core-lightning: fuzz-connectd-handshake-act2: Assertion 'write_count == 1 && "too many calls to io_write()"' ([details]())
- core-lightning: fuzz-cryptomsg: Assertion 'cryptomsg_decrypt_body(buf, &cs_in, buf) == NULL' ([details]())
- core-lightning: fuzz-bolt12-bech32-decode: index 128 out of bounds for type 'const int8_t[128]' ([details](https://github.com/ElementsProject/lightning/pull/7322))
- lnd: FuzzProbability: normalization factor is zero ([details](https://github.com/lightningnetwork/lnd/issues/9085))
- lnd: FuzzReplyChannelRange: failed to encode message to buffer ([details](https://github.com/lightningnetwork/lnd/pull/9084))
- bitcoin: wallet_bdb_parser: BDB builtin encryption is not supported ([details](https://github.com/bitcoin/bitcoin/issues/30166))
- bitcoin: rpc: runtime error: reference binding to null pointer of type 'const value_type' ([details](https://github.com/bitcoin/bitcoin/pull/29855))
- bitcoin: script: Assertion '!extract_destination_ret' failed ([details](https://github.com/bitcoin/bitcoin/issues/30615))
- bitcoin: scriptpubkeyman: heap-buffer-overflow miniscript.cpp in CScript BuildScript ([details](https://github.com/bitcoin/bitcoin/issues/30864))
- bitcoin: p2p_headers_presync: Assertion 'total_work < chainman.MinimumChainWork()' failed ([details](https://github.com/bitcoin/bitcoin/pull/31213))
- bitcoin: connman: terminate called after throwing an instance of 'std::bad_alloc' ([details]())
- bitcoin #30243: mocked_descriptor_parse: Assertion '(leaf_version & ~TAPROOT_LEAF_MASK) == 0' failed ([details](https://github.com/bitcoin/bitcoin/pull/30243#issuecomment-2169240015))
- bitcoin #31244: various descriptor parsing crashes ([details](https://github.com/bitcoin/bitcoin/pull/31244#issuecomment-2527475671))
- bitcoin #28584: null-ptr deref ([details](https://github.com/bitcoin/bitcoin/pull/28584#issuecomment-2527495228))
- bitcoin #28584: use of uninitialized memory ([details](https://github.com/bitcoin/bitcoin/pull/28584#issuecomment-2531288821))