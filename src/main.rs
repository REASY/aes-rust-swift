use aes::cipher::{block_padding::Pkcs7, BlockEncryptMut, KeyIvInit};
use aes_gcm::aead::{Aead, Nonce};
use hex::decode;
use std::time::Instant;

use aes_gcm::aead::consts::U16;
type Aes128GcmAsSwift = aes_gcm::AesGcm<aes::Aes128, U16>;

fn aes_cbc(data: String, key: Vec<u8>, iv: Vec<u8>, iterations: u32) {
    type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;

    let start_time = Instant::now();
    let data_bytes = data.as_bytes();
    let mut buf = [0u8; 48];
    let mut total_len: usize = 0;
    for _ in 0..iterations {
        let encryptor = Aes128CbcEnc::new_from_slices(&key, &iv).unwrap();
        let ct = encryptor
            .encrypt_padded_b2b_mut::<Pkcs7>(&data_bytes, &mut buf)
            .unwrap();
        // println!("{}", hex::encode(ct.clone()));
        total_len += ct.len();
    }
    let duration_sec = start_time.elapsed().as_millis() as f64 / 1000.0;
    println!(
        "AES128 CBC run {} times took {} seconds. total_len dummy value is {}",
        iterations, duration_sec, total_len
    );
}

fn aes_gsm(data: String, key: Vec<u8>, iv: Vec<u8>, iterations: u32) {
    use aes::cipher::typenum::ToInt;
    use aes_gcm::KeyInit;

    assert_eq!(iv.len(), U16::to_int());

    let start_time = Instant::now();
    let data_bytes = data.as_bytes();
    let mut total_len: usize = 0;
    for _ in 0..iterations {
        let nonce = Nonce::<Aes128GcmAsSwift>::clone_from_slice(iv.as_slice());
        let ct = Aes128GcmAsSwift::new_from_slice(&key)
            .unwrap()
            .encrypt(&nonce, data_bytes)
            .unwrap();
        // println!("{}", hex::encode(ct.clone()));
        total_len += ct.len();
    }
    let duration_sec = start_time.elapsed().as_millis() as f64 / 1000.0;
    println!(
        "AES128 GSM run {} times took {} seconds. total_len dummy value is {}",
        iterations, duration_sec, total_len
    );
}

fn aes_gsm_reuse(data: String, key: Vec<u8>, iv: Vec<u8>, iterations: u32) {
    use aes::cipher::typenum::ToInt;
    use aes_gcm::KeyInit;

    assert_eq!(iv.len(), U16::to_int());

    let start_time = Instant::now();
    let data_bytes = data.as_bytes();
    let mut total_len: usize = 0;
    let nonce = Nonce::<Aes128GcmAsSwift>::clone_from_slice(iv.as_slice());
    let encryptor = Aes128GcmAsSwift::new_from_slice(&key).unwrap();
    for _ in 0..iterations {
        let ct = encryptor.encrypt(&nonce, data_bytes).unwrap();
        // println!("{}", hex::encode(ct.clone()));
        total_len += ct.len();
    }
    let duration_sec = start_time.elapsed().as_millis() as f64 / 1000.0;
    println!(
        "AES128 GSM with reusable encryptor run {} times took {} seconds. total_len dummy value is {}",
        iterations, duration_sec, total_len
    );
}

fn main() {
    let key = decode("000102030405060708090a0b0c0d0e0f").unwrap();
    let iv = decode("0f0e0d0c0b0a09080706050403020100").unwrap();
    let data = "Benchmarking AES encryption in Rust".to_string();
    let iterations = 10_000_000;

    aes_cbc(data.clone(), key.clone(), iv.clone(), iterations);
    aes_gsm(data.clone(), key.clone(), iv.clone(), iterations);

    aes_gsm_reuse(data, key, iv, iterations);
}
