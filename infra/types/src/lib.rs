use std::hash::{Hash, Hasher};
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use serde_with::{base64::Base64, serde_as};

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum Language {
    C,
    Cpp,
    Rust,
    Go,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum FuzzEngine {
    LibFuzzer,
    AflPlusPlus,
    SemSan,
    None,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum Sanitizer {
    Undefined,
    Address,
    Coverage,            // Only for FuzzEngine::None
    CmpLog,              // Only for FuzzEngine::AflPlusPlus
    ValueProfile,        // Only for FuzzEngine::LibFuzzer
    SemSan(SemSanBuild), // Only in combination with FuzzEngine::AflPlusPlus
    None,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum SemSanBuild {
    // Gcc build types with varying optimization levels
    GccO0,
    GccO1,
    GccO2,
    // Clang build types with varying optimization levels
    ClangO0,
    ClangO1,
    ClangO2,
    // User defined build types
    Custom0,
    Custom1,
    Custom2,
    Custom3,
    Custom4,
    Custom5,
    Custom6,
    Custom7,
    Custom8,
    Custom9,
    Custom10,
    Custom11,
    Custom12,
    Custom13,
    Custom14,
    Custom15,
}

#[derive(PartialEq, Debug, Clone, Copy, Serialize, Deserialize)]
pub enum CpuArchitecture {
    Amd64,
    Arm64,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ProjectConfig {
    pub name: String,
    pub owner: String,
    pub repo: String,
    pub branch: Option<String>,
    pub language: Language,
    pub ccs: Vec<String>,
    pub engines: Option<Vec<FuzzEngine>>,
    pub sanitizers: Option<Vec<Sanitizer>>,
    pub architectures: Option<Vec<CpuArchitecture>>,
    pub fuzz_env_var: Option<String>,
}

impl ProjectConfig {
    pub fn has_sanitizer(&self, sanitizer: &Sanitizer) -> bool {
        if let Some(sanitizers) = self.sanitizers.as_ref() {
            return sanitizers.contains(sanitizer);
        }

        false
    }

    pub fn has_engine(&self, engine: &FuzzEngine) -> bool {
        if let Some(engines) = self.engines.as_ref() {
            return engines.contains(engine);
        }

        false
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct FuzzerStats {
    #[serde(default)]
    pub execs_per_sec: f64,
    #[serde(default)]
    pub stability: Option<f64>,
    #[serde(default)]
    pub corpus_count: u64,
    #[serde(default)]
    pub saved_crashes: u64,
    #[serde(default)]
    pub saved_hangs: u64,
}

impl Hash for FuzzerStats {
    fn hash<H: Hasher>(&self, state: &mut H) {
        format!("{:?}", self).hash(state);
    }
}

#[serde_as]
#[derive(serde::Deserialize, serde::Serialize)]
pub struct ReproducedSolution {
    /// Reproduction exit code:
    ///   - 71: Differential solution
    ///   - 75: ASan crash
    ///   - 76: UBSan crash
    ///   - 77: Regular crash (e.g. due to an assertion)
    ///   - 78: Timeout
    pub code: i32,
    /// Bytes of the input that trigger the solution
    #[serde_as(as = "Base64")]
    pub input: Vec<u8>,
    /// A stack trace for crashes or a flamegraph SVG for timeouts
    #[serde_as(as = "Base64")]
    pub trace: Vec<u8>,
}

pub fn format_image_name(config: &ProjectConfig) -> String {
    format!("fuzzor-{}", &config.name)
}

pub fn get_harness_dir(
    engine: &FuzzEngine,
    sanitizer: &Sanitizer,
    config: &ProjectConfig,
) -> Option<String> {
    if !config.has_engine(engine) || !config.has_sanitizer(sanitizer) {
        // The project was not build for the requested engine or sanitizer, so there exists no path
        // to the requested binary.
        return None;
    }

    match (engine, sanitizer) {
        (FuzzEngine::LibFuzzer, Sanitizer::None) => Some(String::from("libfuzzer")),
        (FuzzEngine::LibFuzzer, Sanitizer::Undefined) => Some(String::from("libfuzzer_ubsan")),
        (FuzzEngine::LibFuzzer, Sanitizer::Address) => Some(String::from("libfuzzer_asan")),
        (FuzzEngine::LibFuzzer, Sanitizer::Coverage) => None,
        (FuzzEngine::LibFuzzer, Sanitizer::CmpLog) => None,
        (FuzzEngine::LibFuzzer, Sanitizer::ValueProfile) => None,
        (FuzzEngine::LibFuzzer, Sanitizer::SemSan(_)) => None,

        (FuzzEngine::AflPlusPlus, Sanitizer::None) => Some(String::from("aflpp")),
        (FuzzEngine::AflPlusPlus, Sanitizer::Undefined) => Some(String::from("aflpp_ubsan")),
        (FuzzEngine::AflPlusPlus, Sanitizer::Address) => Some(String::from("aflpp_asan")),
        (FuzzEngine::AflPlusPlus, Sanitizer::Coverage) => None,
        (FuzzEngine::AflPlusPlus, Sanitizer::CmpLog) => Some(String::from("aflpp_cmplog")),
        (FuzzEngine::AflPlusPlus, Sanitizer::ValueProfile) => None,
        (FuzzEngine::AflPlusPlus, Sanitizer::SemSan(t)) => Some(format!("semsan_{:?}", t)),

        (FuzzEngine::SemSan, Sanitizer::None) => None,
        (FuzzEngine::SemSan, Sanitizer::Undefined) => None,
        (FuzzEngine::SemSan, Sanitizer::Address) => None,
        (FuzzEngine::SemSan, Sanitizer::Coverage) => None,
        (FuzzEngine::SemSan, Sanitizer::CmpLog) => None,
        (FuzzEngine::SemSan, Sanitizer::ValueProfile) => None,
        (FuzzEngine::SemSan, Sanitizer::SemSan(_)) => None,

        (FuzzEngine::None, Sanitizer::None) => None,
        (FuzzEngine::None, Sanitizer::Undefined) => None,
        (FuzzEngine::None, Sanitizer::Address) => None,
        (FuzzEngine::None, Sanitizer::Coverage) => Some(String::from("coverage")),
        (FuzzEngine::None, Sanitizer::CmpLog) => None,
        (FuzzEngine::None, Sanitizer::ValueProfile) => None,
        (FuzzEngine::None, Sanitizer::SemSan(_)) => None,
        // Note: Make sure to explicitly specify all possible cases here, so the compiler warns us
        // when we add support for new sanitizers and forget to edit this.
    }
}

/// Get the path the binary for a harness.
pub fn get_harness_binary(
    engine: &FuzzEngine,
    sanitizer: &Sanitizer,
    harness: &str,
    config: &ProjectConfig,
) -> Option<PathBuf> {
    let harness_dir = get_harness_dir(engine, sanitizer, config);

    // For projects that use an env variable to select the fuzz harness to run, we expect a binary
    // called "fuzz" instead of an individual binary per harness.
    let binary_name = config.fuzz_env_var.as_deref().map_or(harness, |_| "fuzz");

    harness_dir.map(|dir| PathBuf::from(format!("/workdir/out/{}/{}", dir, binary_name)))
}
