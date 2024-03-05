use clap::Parser;

use fuzzor_infra::*;

#[derive(Parser, Debug)]
struct Options {
    #[arg(help = "Config file to validate", required = true)]
    config: String,
}

fn main() {
    let opts = Options::parse();

    let config = std::fs::read_to_string(opts.config).unwrap();
    match serde_yaml::from_str(&config).unwrap() {
        ProjectConfig {
            language: Language::Go,
            engines: Some(engines),
            ..
        } if !engines.contains(&FuzzEngine::LibFuzzer) => {
            panic!("Go projects only supports LibFuzzer as fuzz engine")
        }
        ProjectConfig {
            language: Language::Rust,
            engines: Some(engines),
            ..
        } if !engines.contains(&FuzzEngine::LibFuzzer) => {
            panic!("Rust projects only supports LibFuzzer as fuzz engine")
        }
        ProjectConfig {
            language: Language::Rust,
            engines: Some(engines),
            sanitizers: Some(sanitizers),
            ..
        } if !engines.contains(&FuzzEngine::LibFuzzer)
            && matches!(sanitizers.as_slice(), [Sanitizer::None]) =>
        {
            panic!("Rust projects have to configured with just Sanitizer::None")
        }
        ProjectConfig {
            engines: Some(engines),
            sanitizers: Some(sanitizers),
            ..
        } if !engines.contains(&FuzzEngine::LibFuzzer)
            && sanitizers.contains(&Sanitizer::ValueProfile) =>
        {
            panic!("ValueProfile is only supported for LibFuzzer")
        }
        ProjectConfig {
            engines: Some(engines),
            sanitizers: Some(sanitizers),
            ..
        } if !engines.contains(&FuzzEngine::AflPlusPlus)
            && sanitizers.contains(&Sanitizer::CmpLog) =>
        {
            panic!("CmpLog is only supported for AflPlusPlus")
        }
        ProjectConfig {
            engines: Some(engines),
            sanitizers: Some(sanitizers),
            ..
        } if !engines.contains(&FuzzEngine::None) && sanitizers.contains(&Sanitizer::Coverage) => {
            panic!("Coverage sanitizer needs FuzzEngine::None")
        }
        _ => {}
    }
}
