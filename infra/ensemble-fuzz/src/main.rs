pub mod ensemble;
pub mod fuzzer;
pub mod options;

use clap::Parser;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Mutex;

use ensemble::start_ensemble_task;
use fuzzer::{
    recommended_aflpp_settings, AflppFuzzer, HonggFuzzer, LibFuzzer, NativeGoFuzzer, SemSanFuzzer,
    SharedFuzzer,
};
use options::EnsembleOptions;

pub fn ensure_dir(path: PathBuf) -> PathBuf {
    if !path.exists() {
        std::fs::create_dir_all(&path).unwrap();
    }

    path
}

fn num_cores_requested(options: &EnsembleOptions) -> usize {
    let cores = vec![
        options.aflpp_binary.is_some(),
        options.aflpp_cmplog_binary.is_some(),
        options.aflpp_ubsan_binary.is_some(),
        options.aflpp_asan_binary.is_some(),
        options.aflpp_msan_binary.is_some(),
        options.libfuzzer_binary.is_some(),
        options.libfuzzer_ubsan_binary.is_some(),
        options.libfuzzer_asan_binary.is_some(),
        options.libfuzzer_msan_binary.is_some(),
        options.native_go_binary.is_some(),
        options.honggfuzz_binary.is_some(),
        options.libfuzzer_value_profile,
    ];

    cores.into_iter().filter(|b| *b).count()
        + options.libfuzzer_additional_cores as usize
        + options.honggfuzz_additional_cores as usize
        + options.semsan_secondary_binaries.len()
}

fn setup_aflpp_instances(
    options: &EnsembleOptions,
    cores_requested: usize,
    fuzzers: &mut Vec<SharedFuzzer>,
) {
    assert!(num_cpus::get() >= cores_requested);
    let extra_cores = num_cpus::get() - cores_requested;

    let extra_args = options.dictionary.as_ref().map_or(vec![], |d| {
        vec![String::from("-x"), d.to_str().unwrap().to_string()]
    });

    if let Some(binary) = options.aflpp_binary.as_ref() {
        let workspace = options.workspace.join("aflpp");
        let seeds = ensure_dir(workspace.join("corpus"));

        fuzzers.push(Arc::new(Mutex::new(AflppFuzzer::new(
            Some(seeds.clone()),
            workspace.clone(),
            binary.clone(),
            fuzzers.len() as u64,
            extra_args.clone(),
            HashMap::new(),
        ))));

        if let Some(cmplog_bin) = options.aflpp_cmplog_binary.as_ref() {
            let mut args = extra_args.clone();
            args.push("-c".to_string());
            args.push(cmplog_bin.to_str().unwrap().to_string());

            fuzzers.push(Arc::new(Mutex::new(AflppFuzzer::new(
                Some(seeds.clone()),
                workspace.clone(),
                binary.clone(),
                fuzzers.len() as u64,
                args,
                HashMap::new(),
            ))));
        }

        let sanitizer_bins = vec![
            options.aflpp_msan_binary.clone(),
            options.aflpp_ubsan_binary.clone(),
            options.aflpp_asan_binary.clone(),
        ];

        for san in sanitizer_bins.iter() {
            if let Some(binary) = san {
                fuzzers.push(Arc::new(Mutex::new(AflppFuzzer::new(
                    Some(seeds.clone()),
                    workspace.clone(),
                    binary.clone(),
                    fuzzers.len() as u64,
                    extra_args.clone(),
                    HashMap::new(),
                ))));
            }
        }

        if options.aflpp_occupy {
            let (mut args, envs) = recommended_aflpp_settings(extra_cores, options);
            assert!(args.len() == envs.len());

            for (i, args) in args.iter_mut().enumerate() {
                args.extend(extra_args.clone().drain(..));

                fuzzers.push(Arc::new(Mutex::new(AflppFuzzer::new(
                    Some(seeds.clone()),
                    workspace.clone(),
                    binary.clone(),
                    fuzzers.len() as u64,
                    args.to_vec(),
                    envs[i].clone(),
                ))));
            }
        }
    }
}

fn setup_libfuzzer_instances(options: &EnsembleOptions, fuzzers: &mut Vec<SharedFuzzer>) {
    let mut libfuzzer_args = vec![
        String::from("-fork=1"),
        String::from("-ignore_crashes=1"),
        String::from("-ignore_ooms=1"),
        String::from("-ignore_timeouts=1"),
    ];

    if let Some(dict_file) = options.dictionary.as_ref() {
        libfuzzer_args.push(dict_file.to_str().unwrap().to_string());
    }

    if let Some(binary) = options.libfuzzer_binary.as_ref() {
        for i in 0..(options.libfuzzer_additional_cores + 1) {
            let workspace = options.workspace.join(format!("libfuzzer-{}", i));
            let seeds = ensure_dir(workspace.join("corpus"));

            fuzzers.push(Arc::new(Mutex::new(LibFuzzer::new(
                seeds,
                workspace,
                binary.clone(),
                libfuzzer_args.clone(),
                HashMap::new(),
                format!("vanilla-{}", i),
            ))));
        }

        if options.libfuzzer_value_profile {
            let workspace = options.workspace.join("libfuzzer-value-profile");
            let seeds = ensure_dir(workspace.join("corpus"));

            let mut args = libfuzzer_args.clone();
            args.push(String::from("-use_value_profile=1"));

            fuzzers.push(Arc::new(Mutex::new(LibFuzzer::new(
                seeds,
                workspace,
                binary.clone(),
                args,
                HashMap::new(),
                String::from("value-profile"),
            ))));
        }

        let sanitizer_bins = vec![
            ("ubsan", options.libfuzzer_ubsan_binary.clone()),
            ("asan", options.libfuzzer_asan_binary.clone()),
            ("msan", options.libfuzzer_msan_binary.clone()),
        ];

        for (name, bin) in sanitizer_bins.iter() {
            if let Some(bin) = bin {
                let name = format!("libfuzzer-{}", *name);
                let workspace = options.workspace.join(&name);
                let seeds = ensure_dir(workspace.join("corpus"));

                fuzzers.push(Arc::new(Mutex::new(LibFuzzer::new(
                    seeds,
                    workspace,
                    bin.clone(),
                    libfuzzer_args.clone(),
                    HashMap::new(),
                    name,
                ))));
            }
        }
    }
}

fn setup_semsan_instances(options: &EnsembleOptions, fuzzers: &mut Vec<SharedFuzzer>) {
    let mut id = 0;
    if let Some(primary) = &options.semsan_primary_binary {
        for secondary in options.semsan_secondary_binaries.iter() {
            let workdir = options.workspace.join(format!("semsan-{}", id));

            let seeds = workdir.join("seeds");
            let _ = std::fs::create_dir_all(&seeds);

            fuzzers.push(Arc::new(Mutex::new(SemSanFuzzer::new(
                primary.clone(),
                secondary.clone(),
                seeds,
                workdir.join("solutions"),
                workdir.join("pull_corpus"),
                options.semsan_comparator.clone(),
            ))));

            id += 1;
        }
    }
}

fn setup_native_go_instances(options: &EnsembleOptions, fuzzers: &mut Vec<SharedFuzzer>) {
    if let Some(binary) = &options.native_go_binary {
        assert!(fuzzers.is_empty()); // native go fuzzing is not compatible with other engines

        let workdir = options.workspace.join("native-go");

        fuzzers.push(Arc::new(Mutex::new(NativeGoFuzzer::new(
            binary.clone(),
            workdir,
        ))));
    }
}

fn setup_honggfuzz_instances(options: &EnsembleOptions, fuzzers: &mut Vec<SharedFuzzer>) {
    if let Some(binary) = options.honggfuzz_binary.as_ref() {
        let workspace = options.workspace.join("honggfuzz");

        fuzzers.push(Arc::new(Mutex::new(HonggFuzzer::new(
            binary.clone(),
            workspace,
            options.honggfuzz_additional_cores + 1,
        ))));
    }
}

fn setup_fuzzers(options: &EnsembleOptions, cores_requested: usize) -> Vec<SharedFuzzer> {
    let mut fuzzers: Vec<SharedFuzzer> = Vec::new();

    setup_aflpp_instances(options, cores_requested, &mut fuzzers);
    setup_libfuzzer_instances(options, &mut fuzzers);
    setup_honggfuzz_instances(options, &mut fuzzers);
    setup_semsan_instances(options, &mut fuzzers);
    setup_native_go_instances(options, &mut fuzzers);

    fuzzers
}

#[tokio::main]
async fn main() {
    env_logger::init();

    let mut options = EnsembleOptions::parse();

    log::info!("{:?}", options);

    let cores_requested = num_cores_requested(&options);
    if cores_requested > num_cpus::get() {
        panic!("Can't start more fuzz instances than cores available");
    }

    options.workspace = ensure_dir(options.workspace);
    ensure_dir(options.workspace.join("corpus"));
    ensure_dir(options.workspace.join("solutions"));

    let fuzzers = setup_fuzzers(&options, cores_requested);
    if fuzzers.is_empty() {
        panic!("At least one base fuzz engine needs to be specified!");
    }

    let mut child_procs: Vec<tokio::process::Child> = Vec::new();
    for fuzzer in fuzzers.iter() {
        let mut fuzzer = fuzzer.lock().await;
        child_procs.push(fuzzer.start());
    }

    let (ensemble_task, ensemble_quit) = start_ensemble_task(
        fuzzers.clone(),
        options.sync_interval,
        60, // seconds
        options.workspace,
    )
    .await;

    if let Some(max_duration) = options.max_duration {
        // Wait for ctrl-c or the specified max fuzzing duration to be reached.
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {},
            _ = tokio::time::sleep(tokio::time::Duration::from_secs(max_duration)) => {},
        }
    } else {
        tokio::signal::ctrl_c()
            .await
            .expect("could not wait for ctrl-c");
    }

    for proc in child_procs.iter_mut() {
        proc.kill().await.expect("could not kill child");
    }
    for proc in child_procs.iter_mut() {
        proc.wait().await.expect("could not wait for child");
    }

    log::info!("Done fuzzing, ensembling one last time!");
    let _ = ensemble_quit.send(()).await;
    let _ = ensemble_task.await;
}
