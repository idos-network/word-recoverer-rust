use anyhow::{anyhow, Result};
use bip39::{Language, Mnemonic};
use clap::Parser;
use hex;
use rayon::prelude::*;
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use sha2::{Digest as Sha2Digest, Sha256};
use sha3::Keccak256;
use std::fs;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tiny_hderive::bip32::ExtendedPrivKey;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Partial BIP39 seed phrase (e.g., "word1 word2 ... wordN")
    #[arg(short, long)]
    phrase: String,

    /// File containing addresses to check against (one per line)
    #[arg(short, long)]
    addresses: String,

    /// File containing derivation paths to check (one per line)
    /// Default: m/44'/60'/0'/0/0 for Ethereum
    #[arg(short, long)]
    derivations: Option<String>,

    /// Number of indices to check for each derivation path pattern (default: 10)
    #[arg(short = 'i', long, default_value_t = 10)]
    indices: usize,

    /// Position of missing words: "end" (default) or "start"
    #[arg(short = 'm', long, default_value = "end")]
    missing_position: String,

    /// Number of threads to use (0 = all available)
    #[arg(short, long, default_value_t = 0)]
    threads: usize,
}

fn main() -> Result<()> {
    let args = Args::parse();

    // Set thread pool size
    if args.threads > 0 {
        rayon::ThreadPoolBuilder::new()
            .num_threads(args.threads)
            .build_global()
            .unwrap();
    }

    println!("Word Recoverer - BIP39 Seed Phrase Recovery Tool");
    println!("================================================");

    // Parse the partial phrase
    let partial_words: Vec<String> = args
        .phrase
        .split_whitespace()
        .map(|w| w.to_lowercase())
        .collect();

    let provided_words = partial_words.len();
    
    // Auto-detect the expected total based on valid BIP39 lengths
    // Most common are 12, 15, 18, 21, 24 words
    let valid_lengths = [12, 15, 18, 21, 24];
    let expected_total_words = valid_lengths
        .iter()
        .find(|&&len| len > provided_words && len - provided_words <= 3)
        .copied()
        .unwrap_or(24);  // Default to 24 if unclear
    
    let missing_count = expected_total_words - provided_words;

    if missing_count == 0 {
        return Err(anyhow!(
            "No missing words detected. Provided {} words, which is a complete BIP39 phrase.",
            provided_words
        ));
    }
    
    if missing_count > 3 {
        return Err(anyhow!(
            "Too many missing words. Provided: {}, detected {} missing words. Currently supports 1-3 missing words.",
            provided_words,
            missing_count
        ));
    }

    println!("Partial phrase: {} words provided", provided_words);
    println!("Missing words: {} detected (assuming {}-word phrase)", missing_count, expected_total_words);
    
    // Validate missing position argument
    let missing_at_start = match args.missing_position.as_str() {
        "start" => true,
        "end" => false,
        _ => return Err(anyhow!("Invalid missing position. Use 'start' or 'end'")),
    };
    
    println!("Missing position: {}", if missing_at_start { "start" } else { "end" });

    // Load target addresses
    let addresses_content = fs::read_to_string(&args.addresses)?;
    let target_addresses: Vec<String> = addresses_content
        .lines()
        .map(|a| a.trim().to_lowercase())
        .filter(|a| !a.is_empty())
        .collect();

    if target_addresses.is_empty() {
        return Err(anyhow!("No target addresses provided"));
    }

    println!("Target addresses: {} loaded", target_addresses.len());

    // Load derivation paths
    let derivation_paths = if let Some(path_file) = args.derivations {
        let paths_content = fs::read_to_string(&path_file)?;
        paths_content
            .lines()
            .map(|p| p.trim().to_string())
            .filter(|p| !p.is_empty())
            .collect()
    } else {
        // Default to common Ethereum derivation paths with multiple indices
        let mut paths = Vec::new();
        for i in 0..args.indices {  // Check specified number of indices for each pattern
            // Ledger legacy Chrome app
            paths.push(format!("m/44'/60'/0'/{}", i));
            // BIP-44 standard (Trezor/MEW/MetaMask style)
            paths.push(format!("m/44'/60'/0'/0/{}", i));
            // Ledger Live style
            paths.push(format!("m/44'/60'/{}'/0/0", i));
        }
        paths
    };

    println!("Derivation paths: {} loaded", derivation_paths.len());

    // Get BIP39 word list
    let word_list = Language::English.word_list();
    println!("BIP39 word list: {} words", word_list.len());

    // Validate provided words
    for word in &partial_words {
        if !word_list.contains(&word.as_str()) {
            return Err(anyhow!("Invalid BIP39 word: '{}'", word));
        }
    }

    println!("\nStarting recovery process...");
    let start_time = Instant::now();

    // Calculate actual search space considering checksum
    // For 24-word phrase: 256 bits entropy + 8 bits checksum = 264 bits total
    let entropy_bits_missing = match missing_count {
        1 => 3,   // Last word has 11 bits, but 8 are checksum, so only 3 bits of entropy
        2 => 14,  // Last 2 words have 22 bits, but 8 are checksum, so 14 bits of entropy
        3 => 25,  // Last 3 words have 33 bits, but 8 are checksum, so 25 bits of entropy
        _ => return Err(anyhow!("Currently supports 1-3 missing words")),
    };
    
    let actual_combinations = 1usize << entropy_bits_missing;
    println!("Total combinations to check (with checksum optimization): {}", actual_combinations);
    println!("(Without optimization it would be: {})", word_list.len().pow(missing_count as u32));

    let found = Arc::new(AtomicBool::new(false));
    let counter = Arc::new(std::sync::atomic::AtomicUsize::new(0));

    // Generate valid combinations using checksum
    let result = recover_with_checksum(
        &partial_words,
        word_list,
        missing_count,
        &target_addresses,
        &derivation_paths,
        found.clone(),
        counter.clone(),
        missing_at_start,
        expected_total_words,
    );

    let elapsed = start_time.elapsed();

    if let Some((mnemonic, address, path)) = result {
        println!("\n✅ SUCCESS! Found matching seed phrase!");
        println!("Complete phrase: {}", mnemonic);
        println!("Matching address: {}", address);
        println!("Derivation path: {}", path);
        println!("Time taken: {:.2?}", elapsed);
        println!(
            "Combinations checked: {}",
            counter.load(Ordering::Relaxed)
        );
    } else {
        println!("\n❌ No matching seed phrase found");
        println!("Time taken: {:.2?}", elapsed);
        println!(
            "Combinations checked: {}",
            counter.load(Ordering::Relaxed)
        );
    }

    Ok(())
}

fn recover_with_checksum(
    partial_words: &[String],
    word_list: &[&str],
    missing_count: usize,
    target_addresses: &[String],
    derivation_paths: &[String],
    found: Arc<AtomicBool>,
    counter: Arc<std::sync::atomic::AtomicUsize>,
    missing_at_start: bool,
    total_words: usize,
) -> Option<(String, String, String)> {
    if missing_at_start {
        // Handle missing words at the start
        recover_with_checksum_at_start(
            partial_words,
            word_list,
            missing_count,
            target_addresses,
            derivation_paths,
            found,
            counter,
            total_words,
        )
    } else {
        // Handle missing words at the end (original implementation)
        recover_with_checksum_at_end(
            partial_words,
            word_list,
            missing_count,
            target_addresses,
            derivation_paths,
            found,
            counter,
            total_words,
        )
    }
}

fn recover_with_checksum_at_end(
    partial_words: &[String],
    word_list: &[&str],
    _missing_count: usize,
    target_addresses: &[String],
    derivation_paths: &[String],
    found: Arc<AtomicBool>,
    counter: Arc<std::sync::atomic::AtomicUsize>,
    total_words: usize,
) -> Option<(String, String, String)> {
    // Convert partial words to indices
    let mut word_indices = Vec::new();
    for word in partial_words {
        let index = word_list.iter().position(|&w| w == word).unwrap();
        word_indices.push(index);
    }
    
    // Convert indices to bits
    let mut bits = Vec::new();
    for index in &word_indices {
        for i in (0..11).rev() {
            bits.push((index >> i) & 1 == 1);
        }
    }
    
    // Calculate entropy bits based on total word count
    let total_bits = total_words * 11;
    let checksum_bits = total_bits / 33; // 1 bit of checksum per 32 bits of entropy
    let entropy_bits = total_bits - checksum_bits;
    
    // Calculate missing entropy bits (not including checksum)
    let provided_bits = partial_words.len() * 11;
    let entropy_bits_missing = entropy_bits - provided_bits;
    
    let combinations = 1u32 << entropy_bits_missing;
    
    // Try each combination of missing entropy bits
    (0..combinations)
        .into_par_iter()
        .find_map_any(|entropy_suffix| {
            if found.load(Ordering::Relaxed) {
                return None;
            }
            
            // Add the entropy bits
            let mut full_bits = bits.clone();
            for i in (0..entropy_bits_missing).rev() {
                full_bits.push((entropy_suffix >> i) & 1 == 1);
            }
            
            // Convert to bytes for checksum calculation
            let mut entropy_bytes = Vec::new();
            for chunk in full_bits.chunks(8).take(entropy_bits / 8) {
                let mut byte = 0u8;
                for (i, &bit) in chunk.iter().enumerate() {
                    if bit {
                        byte |= 1 << (7 - i);
                    }
                }
                entropy_bytes.push(byte);
            }
            
            // Calculate SHA256 checksum
            let mut hasher = Sha256::new();
            hasher.update(&entropy_bytes);
            let hash = hasher.finalize();
            
            // Take first N bits of hash as checksum
            let checksum_byte = hash[0];
            
            // Add checksum bits to complete the mnemonic
            let mut complete_bits = bits.clone();
            for i in (0..entropy_bits_missing).rev() {
                complete_bits.push((entropy_suffix >> i) & 1 == 1);
            }
            for i in (0..checksum_bits).rev() {
                complete_bits.push((checksum_byte >> i) & 1 == 1);
            }
            
            // Convert complete bits back to word indices
            let mut complete_indices = Vec::new();
            for chunk in complete_bits.chunks(11).take(total_words) {
                let mut index = 0usize;
                for (i, &bit) in chunk.iter().enumerate() {
                    if bit {
                        index |= 1 << (10 - i);
                    }
                }
                complete_indices.push(index);
            }
            
            // Convert indices to words
            let words: Vec<String> = complete_indices
                .iter()
                .map(|&idx| word_list[idx].to_string())
                .collect();
            
            check_phrase(&words, target_addresses, derivation_paths, found.clone(), counter.clone())
        })
}

fn recover_with_checksum_at_start(
    partial_words: &[String],
    word_list: &[&str],
    missing_count: usize,
    target_addresses: &[String],
    derivation_paths: &[String],
    found: Arc<AtomicBool>,
    counter: Arc<std::sync::atomic::AtomicUsize>,
    total_words: usize,
) -> Option<(String, String, String)> {
    // For missing words at start, we still benefit from checksum optimization
    // The last word contains checksum bits, so we can validate as we go
    
    let total_bits = total_words * 11;
    let checksum_bits = total_bits / 33;
    let entropy_bits = total_bits - checksum_bits;
    
    // Convert partial words to indices
    let mut partial_indices = Vec::new();
    for word in partial_words {
        let index = word_list.iter().position(|&w| w == word).unwrap();
        partial_indices.push(index);
    }
    
    // Convert partial indices to bits (these are the ending bits)
    let mut partial_bits = Vec::new();
    for index in &partial_indices {
        for i in (0..11).rev() {
            partial_bits.push((index >> i) & 1 == 1);
        }
    }
    
    // For missing words at start, we need to try different starting entropy
    // The total entropy bits = missing_words * 11 bits
    let missing_bits = missing_count * 11;
    let combinations = 1u64 << missing_bits;
    
    (0..combinations)
        .into_par_iter()
        .find_map_any(|start_bits| {
            if found.load(Ordering::Relaxed) {
                return None;
            }
            
            // Convert start_bits to bit array
            let mut starting_bits = Vec::new();
            for i in (0..missing_bits).rev() {
                starting_bits.push((start_bits >> i) & 1 == 1);
            }
            
            // Combine starting bits with partial bits
            let mut complete_bits = starting_bits.clone();
            complete_bits.extend(&partial_bits);
            
            // Extract entropy bits for checksum calculation
            let mut entropy_bytes = Vec::new();
            for chunk in complete_bits.chunks(8).take(entropy_bits / 8) {
                let mut byte = 0u8;
                for (i, &bit) in chunk.iter().enumerate() {
                    if bit {
                        byte |= 1 << (7 - i);
                    }
                }
                entropy_bytes.push(byte);
            }
            
            // Calculate SHA256 checksum
            let mut hasher = Sha256::new();
            hasher.update(&entropy_bytes);
            let hash = hasher.finalize();
            
            // Extract checksum bits from hash
            let checksum_byte = hash[0];
            let mut expected_checksum_bits = Vec::new();
            for i in (0..checksum_bits).rev() {
                expected_checksum_bits.push((checksum_byte >> i) & 1 == 1);
            }
            
            // Check if the last bits of our complete phrase match the expected checksum
            let actual_checksum_start = entropy_bits;
            let actual_checksum_bits = &complete_bits[actual_checksum_start..actual_checksum_start + checksum_bits];
            
            // If checksum doesn't match, skip this combination
            if actual_checksum_bits != expected_checksum_bits.as_slice() {
                counter.fetch_add(1, Ordering::Relaxed);
                return None;
            }
            
            // Convert complete bits to word indices
            let mut complete_indices = Vec::new();
            for chunk in complete_bits.chunks(11).take(total_words) {
                let mut index = 0usize;
                for (i, &bit) in chunk.iter().enumerate() {
                    if bit {
                        index |= 1 << (10 - i);
                    }
                }
                complete_indices.push(index);
            }
            
            // Convert indices to words
            let words: Vec<String> = complete_indices
                .iter()
                .map(|&idx| word_list[idx].to_string())
                .collect();
            
            check_phrase(&words, target_addresses, derivation_paths, found.clone(), counter.clone())
        })
}

fn check_phrase(
    words: &[String],
    target_addresses: &[String],
    derivation_paths: &[String],
    found: Arc<AtomicBool>,
    counter: Arc<std::sync::atomic::AtomicUsize>,
) -> Option<(String, String, String)> {
    let phrase = words.join(" ");

    // Try to create mnemonic
    let mnemonic = match Mnemonic::parse_in(Language::English, &phrase) {
        Ok(m) => m,
        Err(_) => {
            counter.fetch_add(1, Ordering::Relaxed);
            return None;
        }
    };

    // Get seed from mnemonic
    let seed = mnemonic.to_seed("");

    // Check each derivation path
    for path in derivation_paths {
        if let Ok(address) = derive_address(&seed, path) {
            let addr_lower = address.to_lowercase();
            
            if target_addresses.contains(&addr_lower) {
                found.store(true, Ordering::Relaxed);
                return Some((phrase, address, path.clone()));
            }
        }
    }

    // Update counter and print progress
    let count = counter.fetch_add(1, Ordering::Relaxed);
    if count % 10000 == 0 {
        println!("Checked {} combinations...", count);
    }

    None
}

fn derive_address(seed: &[u8; 64], derivation_path: &str) -> Result<String> {
    // Use the derive function directly with seed and path
    let derived = ExtendedPrivKey::derive(seed, derivation_path)
        .map_err(|e| anyhow!("HD derivation error: {:?}", e))?;
    
    // Get private key bytes
    let private_key_bytes = derived.secret();
    
    // Create secp256k1 context and keys
    let secp = Secp256k1::new();
    let secret_key = SecretKey::from_slice(&private_key_bytes)?;
    let public_key = PublicKey::from_secret_key(&secp, &secret_key);
    
    // Get uncompressed public key (65 bytes)
    let pubkey_bytes = public_key.serialize_uncompressed();
    
    // Skip the first byte (0x04) and hash the remaining 64 bytes
    let mut hasher = Keccak256::new();
    hasher.update(&pubkey_bytes[1..]);
    let hash = hasher.finalize();
    
    // Take the last 20 bytes as the address
    let address_bytes = &hash[12..];
    
    // Format as 0x-prefixed hex string
    Ok(format!("0x{}", hex::encode(address_bytes)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_address() {
        // Test with a known mnemonic
        let mnemonic = Mnemonic::parse_in(
            Language::English,
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        ).unwrap();
        
        let seed = mnemonic.to_seed("");
        let address = derive_address(&seed, "m/44'/60'/0'/0/0").unwrap();
        
        // Known address for this mnemonic and path
        assert_eq!(address.to_lowercase(), "0x9858effd232b4033e47d90003d41ec34ecaeda94");
    }
}
