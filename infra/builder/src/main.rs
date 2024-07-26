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
    ld: &'a str,
    envs: &'a [(&'a str, &'a str)],
}

impl<'a> BuildEnv<'a> {
    fn envs(&self) -> HashMap<&'a str, &'a str> {
        let mut envs = HashMap::new();
        envs.insert("CC", self.cc);
        envs.insert("CXX", self.cxx);
        envs.insert("LD", self.ld);

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
const SANITIZE_UNDEFINED: &str = "-fsanitize=array-bounds,bool,builtin,enum,integer-divide-by-zero,null,return,returns-nonnull-attribute,shift,signed-integer-overflow,unsigned-integer-overflow,unreachable,vla-bound,vptr";
const SANITIZE_UNDEFINED_FUZZER: &str = "-fsanitize=fuzzer,array-bounds,bool,builtin,enum,integer-divide-by-zero,null,return,returns-nonnull-attribute,shift,signed-integer-overflow,unsigned-integer-overflow,unreachable,vla-bound,vptr";
const SANITIZE_UNDEFINED_FUZZER_NO_LINK: &str = "-fsanitize=fuzzer-no-link,array-bounds,bool,builtin,enum,integer-divide-by-zero,null,return,returns-nonnull-attribute,shift,signed-integer-overflow,unsigned-integer-overflow,unreachable,vla-bound,vptr";

async fn build_cpp(
    script: &PathBuf,
    output: &PathBuf,
    engine: &FuzzEngine,
    sanitizer: &Sanitizer,
    config: &ProjectConfig,
) -> Result<(), std::io::Error> {
    let env = match (engine, sanitizer) {
        (FuzzEngine::AflPlusPlus, Sanitizer::SemSan(SemSanBuild::GccO0)) => BuildEnv {
            cc: AFL_GCC_CC,
            cxx: AFL_GCC_CXX,
            ld: AFL_GCC_CC,
            envs: &[("CFLAGS", "-O0"), ("CXXFLAGS", "-O0")],
        },
        (FuzzEngine::AflPlusPlus, Sanitizer::SemSan(SemSanBuild::GccO1)) => BuildEnv {
            cc: AFL_GCC_CC,
            cxx: AFL_GCC_CXX,
            ld: AFL_GCC_CC,
            envs: &[("CFLAGS", "-O1"), ("CXXFLAGS", "-O1")],
        },
        (FuzzEngine::AflPlusPlus, Sanitizer::SemSan(SemSanBuild::GccO2)) => BuildEnv {
            cc: AFL_GCC_CC,
            cxx: AFL_GCC_CXX,
            ld: AFL_GCC_CC,
            envs: &[("CFLAGS", "-O2"), ("CXXFLAGS", "-O2")],
        },
        (FuzzEngine::AflPlusPlus, Sanitizer::SemSan(SemSanBuild::ClangO0)) => BuildEnv {
            cc: AFL_CLANG_CC,
            cxx: AFL_CLANG_CXX,
            ld: AFL_CLANG_CC,
            envs: &[("CFLAGS", "-O0"), ("CXXFLAGS", "-O0")],
        },
        (FuzzEngine::AflPlusPlus, Sanitizer::SemSan(SemSanBuild::ClangO1)) => BuildEnv {
            cc: AFL_CLANG_CC,
            cxx: AFL_CLANG_CXX,
            ld: AFL_CLANG_CC,
            envs: &[("CFLAGS", "-O1"), ("CXXFLAGS", "-O1")],
        },
        (FuzzEngine::AflPlusPlus, Sanitizer::SemSan(SemSanBuild::ClangO2)) => BuildEnv {
            cc: AFL_CLANG_CC,
            cxx: AFL_CLANG_CXX,
            ld: AFL_CLANG_CC,
            envs: &[("CFLAGS", "-O2"), ("CXXFLAGS", "-O2")],
        },
        (FuzzEngine::AflPlusPlus, Sanitizer::SemSan(_)) => BuildEnv {
            cc: AFL_CLANG_CC,
            cxx: AFL_CLANG_CXX,
            ld: AFL_CLANG_CC,
            envs: &[],
        },
        (FuzzEngine::SemSan, Sanitizer::None) => BuildEnv {
            cc: AFL_CLANG_CC,
            cxx: AFL_CLANG_CXX,
            ld: AFL_CLANG_CC,
            envs: &[],
        },
        (FuzzEngine::AflPlusPlus, Sanitizer::None) => BuildEnv {
            cc: AFL_CLANG_CC,
            cxx: AFL_CLANG_CXX,
            ld: AFL_CLANG_CC,
            envs: &[],
        },
        (FuzzEngine::AflPlusPlus, Sanitizer::CmpLog) => BuildEnv {
            cc: AFL_CLANG_CC,
            cxx: AFL_CLANG_CXX,
            ld: AFL_CLANG_CC,
            envs: &[("AFL_LLVM_CMPLOG", "1"), ("CCACHE_DIR", "/ccache_cmplog/")],
        },
        (FuzzEngine::AflPlusPlus, Sanitizer::Undefined) => BuildEnv {
            cc: AFL_CLANG_CC,
            cxx: AFL_CLANG_CXX,
            ld: AFL_CLANG_CC,
            envs: &[
                ("LIB_FUZZING_ENGINE", SANITIZE_UNDEFINED),
                ("CFLAGS", SANITIZE_UNDEFINED),
                ("CXXFLAGS", SANITIZE_UNDEFINED),
            ],
        },
        (FuzzEngine::AflPlusPlus, Sanitizer::Address) => BuildEnv {
            cc: AFL_CLANG_CC,
            cxx: AFL_CLANG_CXX,
            ld: AFL_CLANG_CC,
            envs: &[
                ("LIB_FUZZING_ENGINE", "-fsanitize=address"),
                ("CFLAGS", "-fsanitize=address"),
                ("CXXFLAGS", "-fsanitize=address"),
            ],
        },
        (FuzzEngine::LibFuzzer, Sanitizer::None) => BuildEnv {
            cc: "clang",
            cxx: "clang++",
            ld: "clang",
            envs: &[
                ("LIB_FUZZING_ENGINE", "-fsanitize=fuzzer"),
                ("CFLAGS", "-fsanitize=fuzzer-no-link"),
                ("CXXFLAGS", "-fsanitize=fuzzer-no-link"),
            ],
        },
        (FuzzEngine::LibFuzzer, Sanitizer::Undefined) => BuildEnv {
            cc: "clang",
            cxx: "clang++",
            ld: "clang",
            envs: &[
                ("LIB_FUZZING_ENGINE", SANITIZE_UNDEFINED_FUZZER),
                ("CFLAGS", SANITIZE_UNDEFINED_FUZZER_NO_LINK),
                ("CXXFLAGS", SANITIZE_UNDEFINED_FUZZER_NO_LINK),
            ],
        },
        (FuzzEngine::LibFuzzer, Sanitizer::Address) => BuildEnv {
            cc: "clang",
            cxx: "clang++",
            ld: "clang",
            envs: &[
                ("LIB_FUZZING_ENGINE", "-fsanitize=fuzzer,address"),
                ("CFLAGS", "-fsanitize=fuzzer-no-link,address"),
                ("CXXFLAGS", "-fsanitize=fuzzer-no-link,address"),
            ],
        },
        (FuzzEngine::None, Sanitizer::Coverage) => BuildEnv {
            cc: "clang",
            cxx: "clang++",
            ld: "clang",
            envs: &[
                (
                    "LIB_FUZZING_ENGINE",
                    "-fprofile-instr-generate -fcoverage-mapping",
                ),
                ("CFLAGS", "-fprofile-instr-generate -fcoverage-mapping -O0"),
                (
                    "CXXFLAGS",
                    "-fprofile-instr-generate -fcoverage-mapping -O0",
                ),
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

    let semsan_type = if let (FuzzEngine::AflPlusPlus, Sanitizer::SemSan(t)) = (engine, sanitizer) {
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
