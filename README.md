# Fuzzor

Work in progress continuous fuzzing infrastructure. Mainly build and maintained
to continuously fuzz [Bitcoin Core](https://github.com/bitcoin/bitcoin) but
support for adding and fuzzing other projects is available (see `projects/`).

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

