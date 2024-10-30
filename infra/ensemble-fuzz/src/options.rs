use clap::Parser;
use std::path::PathBuf;

#[derive(Parser, Debug)]
pub struct EnsembleOptions {
    /// AFL++ options
    #[arg(long = "aflpp-binary", help = "Specify a afl++ binary")]
    pub aflpp_binary: Option<PathBuf>,
    #[arg(long = "aflpp-cmplog-binary", help = "Specify a afl++ cmplog binary")]
    pub aflpp_cmplog_binary: Option<PathBuf>,
    #[arg(long = "aflpp-ubsan-binary", help = "Specify a afl++ ubsan binary")]
    pub aflpp_ubsan_binary: Option<PathBuf>,
    #[arg(long = "aflpp-asan-binary", help = "Specify a afl++ asan binary")]
    pub aflpp_asan_binary: Option<PathBuf>,
    #[arg(long = "aflpp-msan-binary", help = "Specify a afl++ msan binary")]
    pub aflpp_msan_binary: Option<PathBuf>,
    #[arg(
        long = "aflpp-occupy",
        help = "Occupy left over CPUs with afl++ instances",
        default_value_t = false
    )]
    pub aflpp_occupy: bool,

    /// LibFuzzer options
    #[arg(long = "libfuzzer-binary", help = "Specify a libFuzzer binary")]
    pub libfuzzer_binary: Option<PathBuf>,
    #[arg(
        long = "libfuzzer-ubsan-binary",
        help = "Specify a libFuzzer ubsan binary"
    )]
    pub libfuzzer_ubsan_binary: Option<PathBuf>,
    #[arg(
        long = "libfuzzer-asan-binary",
        help = "Specify a libFuzzer asan binary"
    )]
    pub libfuzzer_asan_binary: Option<PathBuf>,
    #[arg(
        long = "libfuzzer-value-profile",
        help = "Ensemble a libFuzzer instance configured with -use_value_profile",
        default_value_t = false
    )]
    pub libfuzzer_value_profile: bool,
    #[arg(
        long = "libfuzzer-add-cores",
        help = "Number of additional libFuzzer cores",
        default_value_t = 0
    )]
    pub libfuzzer_additional_cores: u64,

    /// SemSan options
    #[arg(
        long = "semsan-binary",
        help = "Specify the binary for the primary SemSan harness"
    )]
    pub semsan_primary_binary: Option<PathBuf>,
    #[arg(
        long = "semsan-secondary-binary",
        help = "Specify one or more binaries for the secondary SemSan harnesses",
        requires = "semsan_primary_binary"
    )]
    pub semsan_secondary_binaries: Vec<PathBuf>,
    #[arg(
        long = "semsan-comparator",
        help = "Specify the comparator used for semsan instances",
        value_delimiter = ',',
        default_value_t = String::from("equal"),
    )]
    pub semsan_comparator: String,

    /// Native Go options
    #[arg(
        long = "native-go-binary",
        help = "Specify the binary for native go fuzzing"
    )]
    pub native_go_binary: Option<PathBuf>,

    /// Honggfuzz options
    #[arg(long = "honggfuzz-binary", help = "Specify a honggfuzz binary")]
    pub honggfuzz_binary: Option<PathBuf>,
    #[arg(
        long = "honggfuzz-add-cores",
        help = "Number of additional honggfuzz cores",
        default_value_t = 0
    )]
    pub honggfuzz_additional_cores: u64,

    #[arg(
        long = "sync-interval",
        help = "Time between corpus syncs in seconds",
        default_value_t = 600
    )]
    pub sync_interval: u64,
    #[arg(long = "max-duration", help = "Maximum fuzzing duration in seconds")]
    pub max_duration: Option<u64>,
    #[arg(
        long = "dictionary",
        help = "Dictionary file to be used by the fuzzers"
    )]
    pub dictionary: Option<PathBuf>,
    #[arg(long = "workspace", help = "Workspace folder", required = true)]
    pub workspace: PathBuf,
}
