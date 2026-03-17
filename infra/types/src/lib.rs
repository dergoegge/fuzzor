use std::hash::{Hash, Hasher};
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use serde_with::{base64::Base64, serde_as};
use sha2::{Digest, Sha256};

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
    AflPlusPlusNyx,
    HonggFuzz,
    SemSan,
    NativeGo,
    None,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum Sanitizer {
    Undefined,
    Address,
    Memory,
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

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct HarnessConfig {
    pub dictionary: Option<PathBuf>,
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

impl FuzzerStats {
    pub fn has_solutions(&self) -> bool {
        (self.saved_hangs + self.saved_crashes) > 0
    }
}

#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum SolutionCause {
    AsanCrash,
    UbsanCrash,
    MsanCrash,
    Crash,
    SignalCrash,
    Timeout,
    Differential,
}

#[serde_as]
#[derive(serde::Deserialize, serde::Serialize)]
pub struct ReproducedSolution {
    pub cause: SolutionCause,
    /// Input bytes that trigger the solution
    #[serde_as(as = "Base64")]
    pub input: Vec<u8>,
    /// Stack trace for crashes or a flamegraph SVG for timeouts
    #[serde_as(as = "Base64")]
    pub trace: Vec<u8>,
}

impl ReproducedSolution {
    pub fn name(&self) -> String {
        let input_hash = Sha256::digest(&self.input);
        let time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        format!("fuzzor-{}-{:?}-{:x}", time, self.cause, input_hash)
    }
}

/// Startup parameters for a fuzzing campaign, stored once at the beginning of each campaign.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CampaignStartupParams {
    /// Number of CPUs allocated to the campaign
    pub num_cpus: usize,
    /// Campaign duration in seconds
    pub duration_secs: u64,
    /// Fuzzing engines enabled for the campaign
    pub engines: Option<Vec<FuzzEngine>>,
    /// Sanitizers enabled for the campaign
    pub sanitizers: Option<Vec<Sanitizer>>,
    /// Commit hash of the target binary being fuzzed
    pub commit_hash: String,
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
        (FuzzEngine::LibFuzzer, Sanitizer::Memory) => Some(String::from("libfuzzer_msan")),
        (FuzzEngine::LibFuzzer, Sanitizer::Coverage) => None,
        (FuzzEngine::LibFuzzer, Sanitizer::CmpLog) => None,
        (FuzzEngine::LibFuzzer, Sanitizer::ValueProfile) => None,
        (FuzzEngine::LibFuzzer, Sanitizer::SemSan(_)) => None,

        (FuzzEngine::AflPlusPlus | FuzzEngine::AflPlusPlusNyx, Sanitizer::None) => {
            Some(String::from("aflpp"))
        }
        (FuzzEngine::AflPlusPlus, Sanitizer::Undefined) => Some(String::from("aflpp_ubsan")),
        (FuzzEngine::AflPlusPlus | FuzzEngine::AflPlusPlusNyx, Sanitizer::Address) => {
            Some(String::from("aflpp_asan"))
        }
        (FuzzEngine::AflPlusPlus, Sanitizer::Memory) => Some(String::from("aflpp_msan")),
        (FuzzEngine::AflPlusPlus, Sanitizer::Coverage) => None,
        (FuzzEngine::AflPlusPlus, Sanitizer::CmpLog) => Some(String::from("aflpp_cmplog")),
        (FuzzEngine::AflPlusPlus, Sanitizer::ValueProfile) => None,
        (FuzzEngine::AflPlusPlus, Sanitizer::SemSan(t)) => Some(format!("semsan_{:?}", t)),
        (FuzzEngine::AflPlusPlusNyx, _) => None,

        (FuzzEngine::HonggFuzz, Sanitizer::None) => Some(String::from("honggfuzz")),
        (FuzzEngine::HonggFuzz, Sanitizer::Undefined) => Some(String::from("honggfuzz_ubsan")),
        (FuzzEngine::HonggFuzz, Sanitizer::Address) => Some(String::from("honggfuzz_asan")),
        (FuzzEngine::HonggFuzz, Sanitizer::Memory) => Some(String::from("honggfuzz_msan")),
        (FuzzEngine::HonggFuzz, Sanitizer::Coverage) => None,
        (FuzzEngine::HonggFuzz, Sanitizer::CmpLog) => None,
        (FuzzEngine::HonggFuzz, Sanitizer::ValueProfile) => None,
        (FuzzEngine::HonggFuzz, Sanitizer::SemSan(_)) => None,

        (FuzzEngine::SemSan, Sanitizer::None) => Some(String::from("semsan")),
        (FuzzEngine::SemSan, Sanitizer::Undefined) => None,
        (FuzzEngine::SemSan, Sanitizer::Address) => None,
        (FuzzEngine::SemSan, Sanitizer::Memory) => None,
        (FuzzEngine::SemSan, Sanitizer::Coverage) => None,
        (FuzzEngine::SemSan, Sanitizer::CmpLog) => None,
        (FuzzEngine::SemSan, Sanitizer::ValueProfile) => None,
        (FuzzEngine::SemSan, Sanitizer::SemSan(t)) => Some(format!("semsan_{:?}", t)),

        (FuzzEngine::NativeGo, Sanitizer::None) => Some(String::from("native_go")),
        (FuzzEngine::NativeGo, Sanitizer::Undefined) => None,
        (FuzzEngine::NativeGo, Sanitizer::Address) => None,
        (FuzzEngine::NativeGo, Sanitizer::Memory) => None,
        (FuzzEngine::NativeGo, Sanitizer::Coverage) => None,
        (FuzzEngine::NativeGo, Sanitizer::CmpLog) => None,
        (FuzzEngine::NativeGo, Sanitizer::ValueProfile) => None,
        (FuzzEngine::NativeGo, Sanitizer::SemSan(_)) => None,

        (FuzzEngine::None, Sanitizer::None) => None,
        (FuzzEngine::None, Sanitizer::Undefined) => None,
        (FuzzEngine::None, Sanitizer::Address) => None,
        (FuzzEngine::None, Sanitizer::Memory) => None,
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

pub enum AflTool {
    AflFuzz,
    AflCMin,
    AflPlot,
    AflWhatsUp,
    AflTmin,
    AflAddSeeds,
    AflShowMap,
}

impl std::fmt::Display for AflTool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AflTool::AflFuzz => write!(f, "afl-fuzz"),
            AflTool::AflCMin => write!(f, "afl-cmin"),
            AflTool::AflPlot => write!(f, "afl-plot"),
            AflTool::AflWhatsUp => write!(f, "afl-whatsup"),
            AflTool::AflTmin => write!(f, "afl-tmin"),
            AflTool::AflAddSeeds => write!(f, "afl-addseeds"),
            AflTool::AflShowMap => write!(f, "afl-showmap"),
        }
    }
}

pub fn get_afl_tool_path(tool: AflTool) -> String {
    match std::env::var("FUZZOR_AFLPP_BIN_PATH") {
        Ok(path) => PathBuf::from(path)
            .join(tool.to_string())
            .to_str()
            .unwrap()
            .to_string(),
        Err(_) => tool.to_string(),
    }
}
