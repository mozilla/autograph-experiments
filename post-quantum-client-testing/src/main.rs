mod mldsa;
mod ecdsa;
mod rsa;
mod falcon;
mod constants;

use std::{time::Instant};
use std::error::Error;
use sysinfo::System;
use serde::{Deserialize, Serialize};
use constants::*;
use cloud_storage::Client;
use uuid::Uuid;

#[derive(Serialize, Deserialize)]
struct TestResult {
    algorithm: String,
    payload_size: String,
    iterations: i32,
    time_ms: f64,
}

#[derive(Serialize, Deserialize)]
struct SystemInfo {
    os: String,
    total_memory: u64,
    cpu_brand: String,
    cpu_cores: usize,
}

#[derive(Serialize, Deserialize)]
struct PerformanceReport {
    system_info: SystemInfo,
    test_results: Vec<TestResult>,
}

fn test_mldsa_small_payload(test_number: i32) -> TestResult {
    let small_msg = "aGVsbG8=".to_string(); // "hello"

    println!("Testing Small Payload ML-DSA-65:");
    let start = Instant::now();
    for _ in 0..test_number {
        let is_verify = mldsa::verify_signature(MLDSA_SMALL_SIG, MLDSA_PK, &small_msg).unwrap();
        assert!(is_verify, "ML-DSA verification failed!");
    }
    let duration = start.elapsed();
    println!("Completed\n");

    TestResult {
        algorithm: "ML-DSA-65".to_string(),
        payload_size: "small".to_string(),
        iterations: test_number,
        time_ms: duration.as_secs_f64() * 1000.0,
    }
}

 
fn test_mldsa_medium_payload(test_number: i32) -> TestResult {
    let medium_msg = "aGkK".repeat(1024 * 512).to_string(); // "hi" repeatedly (around 1MB)

    println!("Testing Medium Payload ML-DSA-65:");
    let start = Instant::now();
    for _ in 0..test_number {
        let is_verify = mldsa::verify_signature(MLDSA_MEDIUM_SIG, MLDSA_PK, &medium_msg).unwrap();
        assert!(is_verify, "ML-DSA verification failed!");
    }
    let duration = start.elapsed();
    println!("Completed\n");

    TestResult {
        algorithm: "ML-DSA-65".to_string(),
        payload_size: "medium".to_string(),
        iterations: test_number,
        time_ms: duration.as_secs_f64() * 1000.0,
    }
}

fn test_falcon_small_payload(test_number: i32) -> TestResult {
    let small_msg = "aGVsbG8=".to_string(); // "hello"

    println!("Testing Small Payload Falcon-512:");
    let start = Instant::now();
    for _ in 0..test_number {
        let is_verify = falcon::verify_signature(FALCON_SMALL_SIG, FALCON_SMALL_PK, &small_msg).unwrap();
        assert!(is_verify, "Falcon verification failed!");
    }
    let duration = start.elapsed();
    println!("Completed\n");

    TestResult {
        algorithm: "Falcon-512".to_string(),
        payload_size: "small".to_string(),
        iterations: test_number,
        time_ms: duration.as_secs_f64() * 1000.0,
    }
}

fn test_falcon_medium_payload(test_number: i32) -> TestResult {
    let medium_msg = "aGkK".repeat(1024 * 512).to_string(); // "hi" repeatedly (around 1MB)

    println!("Testing Medium Payload Falcon-512:");
    let start = Instant::now();
    for _ in 0..test_number {
        let is_verify = falcon::verify_signature(FALCON_MEDIUM_SIG, FALCON_MEDIUM_PK, &medium_msg).unwrap();
        assert!(is_verify, "Falcon verification failed!");
    }
    let duration = start.elapsed();
    println!("Completed\n");

    TestResult {
        algorithm: "Falcon-512".to_string(),
        payload_size: "medium".to_string(),
        iterations: test_number,
        time_ms: duration.as_secs_f64() * 1000.0,
    }
}

fn test_rsa_small_payload(test_number: i32) -> TestResult {
    let small_msg = "aGVsbG8=".to_string(); // "hello"

    println!("Testing Small Payload Rsa-4096:");
    let start = Instant::now();
    for _ in 0..test_number {
        let is_verify = rsa::verify_signature(RSA_SMALL_SIG, RSA_PK, &small_msg).unwrap();
        assert!(is_verify, "Rsa verification failed!");
    }
    let duration = start.elapsed();
    println!("Completed\n");

    TestResult {
        algorithm: "RSA-4096".to_string(),
        payload_size: "small".to_string(),
        iterations: test_number,
        time_ms: duration.as_secs_f64() * 1000.0,
    }
}

fn test_rsa_medium_payload(test_number: i32) -> TestResult {
    let medium_msg = "aGkK".repeat(1024 * 512).to_string(); // "hi" repeatedly (around 1MB)

    println!("Testing Medium Payload RSA-4096:");
    let start = Instant::now();
    for _ in 0..test_number {
        let is_verify = rsa::verify_signature(RSA_MEDIUM_SIG, RSA_PK, &medium_msg).unwrap();
        assert!(is_verify, "Rsa verification failed!");
    }
    let duration = start.elapsed();
    println!("Completed\n");

    TestResult {
        algorithm: "RSA-4096".to_string(),
        payload_size: "medium".to_string(),
        iterations: test_number,
        time_ms: duration.as_secs_f64() * 1000.0,
    }
}

fn test_ecdsa_small_payload(test_number: i32) -> TestResult {
    let small_msg = "aGVsbG8=".to_string(); // "hello"

    println!("Testing Small Payload ECDSA-384:");
    let start = Instant::now();
    for _ in 0..test_number {
        let is_verify = ecdsa::verify_signature(ECDSA_SMALL_SIG, ECDSA_PK, &small_msg).unwrap();
        assert!(is_verify, "Ecdsa verification failed!");
    }
    let duration = start.elapsed();
    println!("Completed\n");

    TestResult {
        algorithm: "ECDSA-384".to_string(),
        payload_size: "small".to_string(),
        iterations: test_number,
        time_ms: duration.as_secs_f64() * 1000.0,
    }
}

fn test_ecdsa_medium_payload(test_number: i32) -> TestResult {
    let medium_msg = "aGkK".repeat(1024 * 512).to_string(); // "hi" repeatedly (around 1MB)

    println!("Testing Medium Payload ECDSA-384:");
    let start = Instant::now();
    for _ in 0..test_number {
        let is_verify = ecdsa::verify_signature(ECDSA_MEDIUM_SIG, ECDSA_PK, &medium_msg).unwrap();
        assert!(is_verify, "Ecdsa verification failed!");
    }
    let duration = start.elapsed();
    println!("Completed\n");

    TestResult {
        algorithm: "ECDSA-384".to_string(),
        payload_size: "medium".to_string(),
        iterations: test_number,
        time_ms: duration.as_secs_f64() * 1000.0,
    }
}

fn system_info() -> SystemInfo {
    let s = System::new_all();

    SystemInfo {
        os: System::long_os_version().unwrap_or_else(|| "<unknown>".to_owned()),
        total_memory: (s.total_memory() / 1000000000),
        cpu_brand: s.cpus()[0].brand().to_string(),
        cpu_cores: System::physical_core_count().unwrap(),
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {

    let test_number = 1000;
    let mut results = Vec::new();

    println!("Running signature verification with {} iterations:\n", test_number);

    // Running the small payload tests (<1MB)
    results.push(test_mldsa_small_payload(test_number));
    results.push(test_falcon_small_payload(test_number));
    results.push(test_rsa_small_payload(test_number));
    results.push(test_ecdsa_small_payload(test_number));

    // Running the medium payload tests (around 1-2MB)
    results.push(test_mldsa_medium_payload(test_number));
    results.push(test_falcon_medium_payload(test_number));
    results.push(test_rsa_medium_payload(test_number));
    results.push(test_ecdsa_medium_payload(test_number));

    let report = PerformanceReport {
        system_info: system_info(),
        test_results: results,
    };

    let json = serde_json::to_string_pretty(&report).expect("Failed to serialize");
    println!("--PERFORMANCE RESULTS--\n");
    println!("{}", json);
    
    // Check if credentials exist at compile time
    if let Some(creds) = option_env!("SERVICE_ACCOUNT_JSON") {
        unsafe {
            std::env::set_var("SERVICE_ACCOUNT_JSON", creds);
        }
        
        let bucket_name = "pq-experiment-results";
        let filename = format!("results_{}.json", Uuid::new_v4());

        let client = Client::default();
        client.object().create(bucket_name, json.into_bytes(), &filename, "application/json").await?;

        println!("\nResults uploaded to GCS bucket: {}", filename);
    } else {
        println!("\nSkipping GCS upload (no credentials available)");
    }

    Ok(())
}
