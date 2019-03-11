// Copyright (c) Microsoft. All rights reserved.

#![deny(rust_2018_idioms, warnings)]
#![deny(clippy::all, clippy::pedantic)]
//Skip ARM(cross-compile) until I figure out how to run ctest on this.
#![cfg(not(any(target_arch = "arm", target_arch = "aarch64")))]

use std::env;
use std::path::Path;
use std::process::Command;

#[test]
fn run_ctest() {
    // Run iot-hsm-c tests
    println!("Start Running ctest for HSM library");
    let out_dir = env::var("OUT_DIR").expect("Did not find OUT_DIR in build environment");
    let out_path = Path::new(&out_dir);

    let build_path = out_path.join("build");

    #[cfg(windows)]
    {
        let enclave_source_path = out_path
            .join("bin")
            .join("enc.signed.dll");

        let enc_target_path_test_1 = build_path
            .join("tests")
            .join("edge_hsm_sas_auth_int")
            .join("Release")
            .join("enc.signed.dll");
        let enc_target_path_test_2 = build_path
            .join("tests")
            .join("edge_hsm_crypto_int")
            .join("Release")
            .join("enc.signed.dll");
        let enc_target_path_test_3 = build_path
            .join("tests")
            .join("edge_hsm_store_int")
            .join("Release")
            .join("enc.signed.dll");

        if fs::copy(&enclave_source_path, enc_target_path_test_1).is_err() {
            println!("#Failed to copy the HSM enclave to the directory where {} is located", "edge_hsm_sas_auth_int");
        }
        if fs::copy(&enclave_source_path, enc_target_path_test_2).is_err() {
            println!("#Failed to copy the HSM enclave to the directory where {} is located", "edge_hsm_crypto_int");
        }
        if fs::copy(&enclave_source_path, enc_target_path_test_3).is_err() {
            println!("#Failed to copy the HSM enclave to the directory where {} is located", "edge_hsm_store_int");
        }
    }

    let test_output = Command::new("ctest")
        .arg("-C")
        .arg("Release")
        .arg("-VV")
        .arg(format!("-j {}", num_cpus::get()))
        .current_dir(build_path)
        .output()
        .expect("failed to execute ctest");
    println!("status: {}", test_output.status);
    println!("stdout: {}", String::from_utf8_lossy(&test_output.stdout));
    println!("stderr: {}", String::from_utf8_lossy(&test_output.stderr));
    if !test_output.status.success() {
        panic!("Running CTest failed.");
    }
    println!("Done Running ctest for HSM library");
}
