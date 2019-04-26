// Copyright 2019 ???
//
// TODO: LICENSE TEXT
//

#[macro_use]
extern crate lazy_static;

mod math;

/// Config Struct
#[derive( Debug, Clone, PartialEq, Eq)]
pub struct ShamirMnemonicConfig {
	/// The length of the radix in bits
	radix_bits: u8,
	/// The length of the random Identifier in bits
	id_length_bits: u8,
	/// The length of the iteration exponent in bits
	iteration_exp_length_bits: u8,
	/// The maximum number of shares that can be created
	max_share_count: u8,
	/// The length of the RS1024 checksum in words
	checksum_length_words: u8,
	/// The length of the digest of the shared secret in bytes
	digest_length_bytes: u8,
	/// The customization string used in the RS1024 checksum and in the PBKDF2 salt
	customization_string: Vec<u8>,
	/// The minimum allowed entropy of the master secret
	min_strength_bits: u16,
	/// The minimum number of iterations to use in PBKDF2
	min_iteration_count: u16,
	/// The number of rounds to use in the Feistel cipher
	round_count: u8,
	/// The index of the share containing the shared secret
	secret_index: u8,
	/// The index of the share containing the digest of the shared secret
	digest_index: u8,
}

impl Default for ShamirMnemonicConfig {
	fn default() -> Self {
		ShamirMnemonicConfig {
			radix_bits: 10,
			id_length_bits: 15,
			iteration_exp_length_bits: 5,
			max_share_count: 16,
			checksum_length_words: 3,
			digest_length_bytes: 4,
			customization_string: b"shamir".to_vec(),
			min_strength_bits: 128,
			min_iteration_count: 10000,
			round_count: 4,
			secret_index: 255,
			digest_index: 254,
		}
	}
}

/// Main Struct
pub struct ShamirMnemonic {
	/// Configuration values
	config: ShamirMnemonicConfig,
	/// The number of words in the word list
	radix: u16,
	/// The length of the random identifier and iteration exponent in words
	id_exp_length_words: u8,
		/// The length of mnemonic is words without the share value
	metadata_length_words: u8,
	/// The minimum allowed length of the mnemonic in words
	min_mnemonic_length_words: u8,
}

impl ShamirMnemonic {
	/// Create new
	pub fn new(config: &ShamirMnemonicConfig) -> ShamirMnemonic {
		let radix = 2u16.pow(config.radix_bits as u32);
		let id_exp_length_words = (config.id_length_bits + config.iteration_exp_length_bits) / config.radix_bits;
		let metadata_length_words = id_exp_length_words + 2 + config.checksum_length_words;
		let min_mnemonic_length_words = metadata_length_words + (config.min_strength_bits as f64 / 10f64).ceil() as u8;
		ShamirMnemonic {
			config: config.to_owned(),
			radix,
			id_exp_length_words,
			metadata_length_words,
			min_mnemonic_length_words,
		}
	}
}

#[cfg(test)]
mod tests {
	#[test]
	fn it_works() {
		assert_eq!(2 + 2, 4);
	}
}
