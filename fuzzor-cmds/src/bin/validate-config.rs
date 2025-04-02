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
    let config = serde_yaml::from_str(&config).unwrap();
    println!("{:#?}", config);

    match config {
        ProjectConfig {
            language: Language::Go,
            engines: Some(engines),
            ..
        } if !engines.contains(&FuzzEngine::NativeGo) || engines.len() > 1 => {
            eprintln!("Go projects only support NativeGo as fuzz engine");
            std::process::exit(1);
        }
        ProjectConfig {
            language: Language::Rust,
            engines: Some(engines),
            ..
        } if !engines.contains(&FuzzEngine::LibFuzzer) => {
            eprintln!("Rust projects only support LibFuzzer as fuzz engine");
            std::process::exit(1);
        }
        ProjectConfig {
            language: Language::Rust,
            engines: Some(engines),
            sanitizers: Some(sanitizers),
            ..
        } if !engines.contains(&FuzzEngine::LibFuzzer)
            && matches!(sanitizers.as_slice(), [Sanitizer::None]) =>
        {
            eprintln!("Rust projects have to configured with just Sanitizer::None");
            std::process::exit(1);
        }
        ProjectConfig {
            engines: Some(engines),
            sanitizers: Some(sanitizers),
            ..
        } if !engines.contains(&FuzzEngine::LibFuzzer)
            && sanitizers.contains(&Sanitizer::ValueProfile) =>
        {
            eprintln!("ValueProfile is only supported for LibFuzzer");
            std::process::exit(1);
        }
        ProjectConfig {
            engines: Some(engines),
            sanitizers: Some(sanitizers),
            ..
        } if !engines.contains(&FuzzEngine::AflPlusPlus)
            && sanitizers.contains(&Sanitizer::CmpLog) =>
        {
            eprintln!("CmpLog is only supported for AflPlusPlus");
            std::process::exit(1);
        }
        ProjectConfig {
            engines: Some(engines),
            sanitizers: Some(sanitizers),
            ..
        } if !engines.contains(&FuzzEngine::None) && sanitizers.contains(&Sanitizer::Coverage) => {
            eprintln!("Coverage sanitizer needs FuzzEngine::None");
            std::process::exit(1);
        }
        ProjectConfig {
            engines: Some(engines),
            sanitizers: Some(sanitizers),
            ..
        } if engines.contains(&FuzzEngine::SemSan)
            && sanitizers
                .iter()
                .filter(|s| matches!(s, &Sanitizer::SemSan(_)))
                .count()
                == 0 =>
        {
            eprintln!(
                "SemSan engine can only be used with at least one user defined SemSan sanitizer. Include SemSan(n) in your config and provide a build step for `n`."
            );
            std::process::exit(1);
        }
        _ => {}
    }
}
