use std::collections::HashMap;
use std::path::PathBuf;

use clap::Parser;
use fuzzor_infra::{get_harness_dir, FuzzEngine, Language, ProjectConfig, Sanitizer, SemSanBuild};
use tokio::{fs, process::Command};

#[derive(Parser, Debug)]
struct Options {
    #[arg(help = "Path to project config", required = true)]
    pub config: PathBuf,
    #[arg(help = "Path to project build script", required = true)]
    pub build_script: PathBuf,
    #[arg(help = "Path to build destination", required = true)]
    pub output: PathBuf,
}

struct BuildEnv<'a> {
    cc: &'a str,
    cxx: &'a str,
    envs: &'a [(&'a str, &'a str)],
}

impl<'a> BuildEnv<'a> {
    fn envs(&self) -> HashMap<&'a str, &'a str> {
        let mut envs = HashMap::new();
        envs.insert("CC", self.cc);
        envs.insert("CXX", self.cxx);

        for (var, value) in self.envs.iter() {
            envs.insert(var, value);
        }

        if !envs.contains_key("CCACHE_DIR") {
            envs.insert("CCACHE_DIR", "/ccache/");
        }

        envs
    }
}

const AFL_CLANG_CC: &str = "afl-clang-fast";
const AFL_CLANG_CXX: &str = "afl-clang-fast++";
const AFL_GCC_CC: &str = "afl-gcc-fast";
const AFL_GCC_CXX: &str = "afl-g++-fast";
const SANITIZE_UNDEFINED_LD: &str = "-fsanitize=array-bounds,bool,builtin,enum,integer-divide-by-zero,null,return,returns-nonnull-attribute,shift,signed-integer-overflow,unsigned-integer-overflow,unreachable,vla-bound,vptr";
const SANITIZE_UNDEFINED: &str = "-fsanitize=array-bounds,bool,builtin,enum,integer-divide-by-zero,null,return,returns-nonnull-attribute,shift,signed-integer-overflow,unsigned-integer-overflow,unreachable,vla-bound,vptr -O2";
const SANITIZE_UNDEFINED_FUZZER: &str = "-fsanitize=fuzzer,array-bounds,bool,builtin,enum,integer-divide-by-zero,null,return,returns-nonnull-attribute,shift,signed-integer-overflow,unsigned-integer-overflow,unreachable,vla-bound,vptr";
const SANITIZE_UNDEFINED_FUZZER_NO_LINK: &str = "-fsanitize=fuzzer-no-link,array-bounds,bool,builtin,enum,integer-divide-by-zero,null,return,returns-nonnull-attribute,shift,signed-integer-overflow,unsigned-integer-overflow,unreachable,vla-bound,vptr -O2";

async fn build_cpp(
    script: &PathBuf,
    output: &PathBuf,
    engine: &FuzzEngine,
    sanitizer: &Sanitizer,
    config: &ProjectConfig,
) -> Result<(), std::io::Error> {
    let env = match (engine, sanitizer) {
        (FuzzEngine::SemSan, Sanitizer::SemSan(SemSanBuild::GccO0)) => BuildEnv {
            cc: AFL_GCC_CC,
            cxx: AFL_GCC_CXX,
            envs: &[("CFLAGS", "-O0"), ("CXXFLAGS", "-O0")],
        },
        (FuzzEngine::SemSan, Sanitizer::SemSan(SemSanBuild::GccO1)) => BuildEnv {
            cc: AFL_GCC_CC,
            cxx: AFL_GCC_CXX,
            envs: &[("CFLAGS", "-O1"), ("CXXFLAGS", "-O1")],
        },
        (FuzzEngine::SemSan, Sanitizer::SemSan(SemSanBuild::GccO2)) => BuildEnv {
            cc: AFL_GCC_CC,
            cxx: AFL_GCC_CXX,
            envs: &[("CFLAGS", "-O2"), ("CXXFLAGS", "-O2")],
        },
        (FuzzEngine::SemSan, Sanitizer::SemSan(SemSanBuild::ClangO0)) => BuildEnv {
            cc: AFL_CLANG_CC,
            cxx: AFL_CLANG_CXX,
            envs: &[("CFLAGS", "-O0"), ("CXXFLAGS", "-O0")],
        },
        (FuzzEngine::SemSan, Sanitizer::SemSan(SemSanBuild::ClangO1)) => BuildEnv {
            cc: AFL_CLANG_CC,
            cxx: AFL_CLANG_CXX,
            envs: &[("CFLAGS", "-O1"), ("CXXFLAGS", "-O1")],
        },
        (FuzzEngine::SemSan, Sanitizer::SemSan(SemSanBuild::ClangO2)) => BuildEnv {
            cc: AFL_CLANG_CC,
            cxx: AFL_CLANG_CXX,
            envs: &[("CFLAGS", "-O2"), ("CXXFLAGS", "-O2")],
        },
        (FuzzEngine::SemSan, Sanitizer::SemSan(_)) => BuildEnv {
            cc: AFL_CLANG_CC,
            cxx: AFL_CLANG_CXX,
            envs: &[],
        },
        (FuzzEngine::SemSan, Sanitizer::None) => BuildEnv {
            cc: AFL_CLANG_CC,
            cxx: AFL_CLANG_CXX,
            envs: &[],
        },
        (FuzzEngine::AflPlusPlus, Sanitizer::None) => BuildEnv {
            cc: AFL_CLANG_CC,
            cxx: AFL_CLANG_CXX,
            envs: &[],
        },
        (FuzzEngine::AflPlusPlus, Sanitizer::CmpLog) => BuildEnv {
            cc: AFL_CLANG_CC,
            cxx: AFL_CLANG_CXX,
            envs: &[
                ("AFL_LLVM_CMPLOG", "1"),
                ("CCACHE_DIR", "/ccache_cmplog/"),
                ("CFLAGS", "-O2"),
                ("CXXFLAGS", "-O2"),
            ],
        },
        (FuzzEngine::AflPlusPlus, Sanitizer::Undefined) => BuildEnv {
            cc: AFL_CLANG_CC,
            cxx: AFL_CLANG_CXX,
            envs: &[
                ("LIB_FUZZING_ENGINE", SANITIZE_UNDEFINED_LD),
                ("CFLAGS", SANITIZE_UNDEFINED),
                ("CXXFLAGS", SANITIZE_UNDEFINED),
            ],
        },
        #[cfg(not(target_arch = "x86_64"))]
        // Disable afl++ asan builds on x86_64 for now: https://github.com/dergoegge/fuzzor/issues/4
        (FuzzEngine::AflPlusPlus, Sanitizer::Address) => BuildEnv {
            cc: AFL_CLANG_CC,
            cxx: AFL_CLANG_CXX,
            envs: &[
                ("AFL_USE_ASAN", "1"),
                ("CCACHE_DIR", "/ccache_asan/"),
                ("CFLAGS", "-O2"),
                ("CXXFLAGS", "-O2"),
            ],
        },
        (FuzzEngine::AflPlusPlus, Sanitizer::Memory) => BuildEnv {
            cc: AFL_CLANG_CC,
            cxx: AFL_CLANG_CXX,
            envs: &[
                ("CFLAGS", "-fsanitize=memory,fuzzer-no-link -fsanitize-memory-track-origins=2 -fno-omit-frame-pointer -g -O1 -fno-optimize-sibling-calls"),
                ("CXXFLAGS", "-fsanitize=memory,fuzzer-no-link -fsanitize-memory-track-origins=2 -fno-omit-frame-pointer -g -O1 -fno-optimize-sibling-calls -nostdinc++ -nostdlib++ -isystem /libcxx_msan/include/c++/v1 -L/libcxx_msan/lib -Wl,-rpath,/libcxx_msan/lib -lc++ -lc++abi -lpthread -Wno-unused-command-line-argument"),
            ],
        },
        (FuzzEngine::LibFuzzer, Sanitizer::None) => BuildEnv {
            cc: "clang",
            cxx: "clang++",
            envs: &[
                ("LIB_FUZZING_ENGINE", "-fsanitize=fuzzer"),
                ("CFLAGS", "-O2 -fsanitize=fuzzer-no-link"),
                ("CXXFLAGS", "-O2 -fsanitize=fuzzer-no-link"),
            ],
        },
        (FuzzEngine::LibFuzzer, Sanitizer::Undefined) => BuildEnv {
            cc: "clang",
            cxx: "clang++",
            envs: &[
                ("LIB_FUZZING_ENGINE", SANITIZE_UNDEFINED_FUZZER),
                ("CFLAGS", SANITIZE_UNDEFINED_FUZZER_NO_LINK),
                ("CXXFLAGS", SANITIZE_UNDEFINED_FUZZER_NO_LINK),
            ],
        },
        (FuzzEngine::LibFuzzer, Sanitizer::Address) => BuildEnv {
            cc: "clang",
            cxx: "clang++",
            envs: &[
                ("LIB_FUZZING_ENGINE", "-fsanitize=fuzzer,address"),
                ("CFLAGS", "-O2 -fsanitize=fuzzer-no-link,address"),
                ("CXXFLAGS", "-O2 -fsanitize=fuzzer-no-link,address"),
            ],
        },
        (FuzzEngine::LibFuzzer, Sanitizer::Memory) => BuildEnv {
            cc: "clang",
            cxx: "clang++",
            envs: &[
                ("LIB_FUZZING_ENGINE", "-fsanitize=fuzzer,memory"),
                ("CFLAGS", "-fsanitize=memory,fuzzer-no-link -fsanitize-memory-track-origins=2 -fno-omit-frame-pointer -g -O1 -fno-optimize-sibling-calls"),
                ("CXXFLAGS", "-fsanitize=memory,fuzzer-no-link -fsanitize-memory-track-origins=2 -fno-omit-frame-pointer -g -O1 -fno-optimize-sibling-calls -nostdinc++ -nostdlib++ -isystem /libcxx_msan/include/c++/v1 -L/libcxx_msan/lib -Wl,-rpath,/libcxx_msan/lib -lc++ -lc++abi -lpthread -Wno-unused-command-line-argument"),
            ],
        },
        (FuzzEngine::HonggFuzz, Sanitizer::None) => BuildEnv {
            cc: "hfuzz-clang",
            cxx: "hfuzz-clang++",
            envs: &[
                ("LIB_FUZZING_ENGINE", ""),
                ("CFLAGS", "-O2"),
                ("CXXFLAGS", "-O2"),
            ],
        },
        //(FuzzEngine::HonggFuzz, Sanitizer::Undefined) => BuildEnv {
        //    cc: "hfuzz-clang",
        //    cxx: "hfuzz-clang++",
        //    envs: &[
        //        ("LIB_FUZZING_ENGINE", "-fsanitize=undefined"),
        //        ("CFLAGS", "-O2 -fsanitize=undefined"),
        //        ("CXXFLAGS", "-O2 -fsanitize=undefined"),
        //    ],
        //},
        //(FuzzEngine::HonggFuzz, Sanitizer::Address) => BuildEnv {
        //    cc: "hfuzz-clang",
        //    cxx: "hfuzz-clang++",
        //    envs: &[
        //        ("LIB_FUZZING_ENGINE", "-fsanitize=address"),
        //        ("CFLAGS", "-O2 -fsanitize=address"),
        //        ("CXXFLAGS", "-O2 -fsanitize=address"),
        //    ],
        //},
        (FuzzEngine::None, Sanitizer::Coverage) => BuildEnv {
            cc: "clang",
            cxx: "clang++",
            envs: &[
                (
                    "CFLAGS",
                    "-fsanitize=fuzzer-no-link -fprofile-instr-generate -fcoverage-mapping -O0",
                ),
                (
                    "CXXFLAGS",
                    "-fsanitize=fuzzer-no-link -fprofile-instr-generate -fcoverage-mapping -O0",
                ),
                ("LIB_FUZZING_ENGINE", "-fsanitize=fuzzer"),
            ],
        },
        (_, _) => return Ok(()),
    };

    let harness_dir = get_harness_dir(engine, sanitizer, config).unwrap();
    let output_dir = output.join(&harness_dir);
    if !output_dir.exists() {
        fs::create_dir_all(&output_dir).await?;
    }

    let mut envs = env.envs();
    envs.insert("FUZZING_ENGINE", &harness_dir);

    let semsan_type = if let (FuzzEngine::SemSan, Sanitizer::SemSan(t)) = (engine, sanitizer) {
        Some(format!("{:?}", t))
    } else {
        None
    };
    if let Some(t) = &semsan_type {
        envs.insert("SEMSAN_BUILD", &t);
    }

    let res = Command::new(script)
        .envs(envs)
        .env("OUT", &output_dir)
        .kill_on_drop(true)
        .status()
        .await?;

    if !res.success() {
        std::process::exit(1);
    }

    Ok(())
}

async fn build_rust(
    script: &PathBuf,
    output: &PathBuf,
    engine: &FuzzEngine,
    sanitizer: &Sanitizer,
    config: &ProjectConfig,
) -> Result<(), std::io::Error> {
    let Some(harness_dir) = get_harness_dir(engine, sanitizer, config) else {
        return Ok(());
    };

    let output_dir = output.join(&harness_dir);
    if !output_dir.exists() {
        fs::create_dir_all(&output_dir).await?;
    }

    let mut envs = HashMap::new();
    envs.insert("FUZZING_ENGINE", &harness_dir);

    let res = Command::new(script)
        .envs(envs)
        .env("OUT", &output_dir)
        .kill_on_drop(true)
        .status()
        .await?;

    if !res.success() {
        std::process::exit(1);
    }

    Ok(())
}

async fn build_go(
    script: &PathBuf,
    output: &PathBuf,
    engine: &FuzzEngine,
    sanitizer: &Sanitizer,
    config: &ProjectConfig,
) -> Result<(), std::io::Error> {
    let Some(harness_dir) = get_harness_dir(engine, sanitizer, config) else {
        return Ok(());
    };

    let output_dir = output.join(&harness_dir);
    if !output_dir.exists() {
        fs::create_dir_all(&output_dir).await?;
    }

    let mut envs = HashMap::new();
    envs.insert("FUZZING_ENGINE", &harness_dir);

    let res = Command::new(script)
        .envs(envs)
        .env("OUT", &output_dir)
        .kill_on_drop(true)
        .status()
        .await?;

    if !res.success() {
        std::process::exit(1);
    }

    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), std::io::Error> {
    let opts = Options::parse();

    let config = fs::read_to_string(opts.config).await?;
    let config: ProjectConfig = serde_yaml::from_str(&config).unwrap();

    match config.language {
        Language::C | Language::Cpp => {
            for engine in config.engines.as_ref().unwrap().iter() {
                for sanitizer in config.sanitizers.as_ref().unwrap().iter() {
                    build_cpp(
                        &opts.build_script,
                        &opts.output,
                        &engine,
                        &sanitizer,
                        &config,
                    )
                    .await?;
                }
            }
        }
        Language::Rust => {
            for engine in config.engines.as_ref().unwrap().iter() {
                for sanitizer in config.sanitizers.as_ref().unwrap().iter() {
                    build_rust(
                        &opts.build_script,
                        &opts.output,
                        &engine,
                        &sanitizer,
                        &config,
                    )
                    .await?;
                }
            }
        }
        Language::Go => {
            for engine in config.engines.as_ref().unwrap().iter() {
                for sanitizer in config.sanitizers.as_ref().unwrap().iter() {
                    build_go(
                        &opts.build_script,
                        &opts.output,
                        &engine,
                        &sanitizer,
                        &config,
                    )
                    .await?;
                }
            }
        }
    }

    Ok(())
}
