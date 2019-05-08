// Copyright 2019 The Grin Developers
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Configuration for the secret sharing engine
//! Changing these values changes compatibility with the original
//! scheme, (and changes would need to be re-tested throughout)
//! but probably best to keep configuration flexible for now

/// Config Struct
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShamirMnemonicConfig {
	/// The length of the radix in bits
	pub radix_bits: u8,
	/// The length of the random Identifier in bits
	pub id_length_bits: u8,
	/// The length of the iteration exponent in bits
	pub iteration_exp_length_bits: u8,
	/// The maximum number of shares that can be created
	pub max_share_count: u8,
	/// The length of the RS1024 checksum in words
	pub checksum_length_words: u8,
	/// The length of the digest of the shared secret in bytes
	pub digest_length_bytes: u8,
	/// The customization string used in the RS1024 checksum and in the PBKDF2 salt
	pub customization_string: Vec<u8>,
	/// The minimum allowed entropy of the master secret
	pub min_strength_bits: u16,
	/// The minimum number of iterations to use in PBKDF2
	pub min_iteration_count: u16,
	/// The number of rounds to use in the Feistel cipher
	pub round_count: u8,
	/// The index of the share containing the shared secret
	pub secret_index: u8,
	/// The index of the share containing the digest of the shared secret
	pub digest_index: u8,
	/// The number of words in the word list
	pub radix: u16,
	/// The length of the random identifier and iteration exponent in words
	pub id_exp_length_words: u8,
	/// The length of mnemonic is words without the share value
	pub metadata_length_words: u8,
	/// The minimum allowed length of the mnemonic in words
	pub min_mnemonic_length_words: u8,
}

impl Default for ShamirMnemonicConfig {
	fn default() -> Self {
		let radix_bits = 10;
		let id_length_bits = 15;
		let iteration_exp_length_bits = 5;
		let max_share_count = 16;
		let checksum_length_words = 3;
		let digest_length_bytes = 4;
		let customization_string = b"shamir".to_vec();
		let min_strength_bits = 128;
		let min_iteration_count = 10000;
		let round_count = 4;
		let secret_index = 255;
		let digest_index = 254;

		// derived values
		let radix = 2u16.pow(radix_bits as u32);
		let id_exp_length_words = (id_length_bits + iteration_exp_length_bits) / radix_bits;
		let metadata_length_words = id_exp_length_words + 2 + checksum_length_words;
		let min_mnemonic_length_words =
			metadata_length_words + (min_strength_bits as f64 / 10f64).ceil() as u8;

		ShamirMnemonicConfig {
			radix_bits,
			id_length_bits,
			iteration_exp_length_bits,
			max_share_count,
			checksum_length_words,
			digest_length_bytes,
			customization_string,
			min_strength_bits,
			min_iteration_count,
			round_count,
			secret_index,
			digest_index,
			radix,
			id_exp_length_words,
			metadata_length_words,
			min_mnemonic_length_words,
		}
	}
}

impl ShamirMnemonicConfig {
	/// Just use defaults for now
	pub fn new() -> Self {
		ShamirMnemonicConfig {
			..Default::default()
		}
	}
}
