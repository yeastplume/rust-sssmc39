// Copyright 2019 ???
//
// TODO: LICENSE TEXT
//

use std::collections::HashMap;

#[macro_use]
extern crate lazy_static;

use error::{Error, ErrorKind};
use rand::{Rng, thread_rng};

use digest::Digest;
use hmac::{Hmac, Mac};
use sha2::Sha256;

mod error;
mod math;

// Create alias for HMAC-SHA256
type HmacSha256 = Hmac<Sha256>;

lazy_static! {
	/// List of ssmc words
	pub static ref WORDLIST: Vec<String> = { include_str!("wordlists/en.txt").split_whitespace().map(|s| s.into()).collect() };
	pub static ref WORD_INDEX_MAP: HashMap<String, usize> = {
		let mut retval = HashMap::new();
		for (i, item) in WORDLIST.iter().enumerate() {
			retval.insert(item.to_owned(), i);
		}
		retval
	};
}

/// Config Struct
#[derive(Debug, Clone, PartialEq, Eq)]
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Share {
	/// Member index, or x value of the member share in the given group
	pub member_index: u8,
	/// Share data
	pub data: Vec<u8>,
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
	/// Generated shares (do we want to hold them here?)
	shares: Vec<Share>,
}

impl ShamirMnemonic {
	/// Create new
	pub fn new(config: &ShamirMnemonicConfig) -> Result<ShamirMnemonic, Error> {
		let radix = 2u16.pow(config.radix_bits as u32);
		let id_exp_length_words =
			(config.id_length_bits + config.iteration_exp_length_bits) / config.radix_bits;
		let metadata_length_words = id_exp_length_words + 2 + config.checksum_length_words;
		let min_mnemonic_length_words =
			metadata_length_words + (config.min_strength_bits as f64 / 10f64).ceil() as u8;
		if WORDLIST.len() != radix as usize {
			return Err(ErrorKind::Config(format!(
				"The wordlist should contain {} words, but it contains {} words.",
				radix,
				WORDLIST.len()
			)))?;
		}
		Ok(ShamirMnemonic {
			config: config.to_owned(),
			radix,
			id_exp_length_words,
			metadata_length_words,
			min_mnemonic_length_words,
			shares: vec![],
		})
	}

	/// split secret
	/// member_threshold, share_count, shared_secret at least 128 bits and a multiple of 16
	/// returns shares
	pub fn split_secret(
		&mut self,
		member_threshold: u8,
		share_count: u8,
		shared_secret: &Vec<u8>,
	) -> Result<(), Error> {
		if member_threshold == 0 || member_threshold > self.config.max_share_count {
			return Err(ErrorKind::Argument(format!(
				"Member threshold must be between 1 and {}",
				self.config.max_share_count
			)))?;
		}
		if share_count < member_threshold || share_count > self.config.max_share_count {
			return Err(ErrorKind::Argument(format!(
				"Share count with given member threshold must be between {} and {}",
				member_threshold, self.config.max_share_count
			)))?;
		}
		if shared_secret.len() <= 16 || shared_secret.len() % 2 != 0 {
			return Err(ErrorKind::Argument(format!(
				"Secret must be at least 16 bytes in length and a multiple of 2",
			)))?;
		}
		// if the threshold is 1, then the digest of the shared secret is not used
		if member_threshold == 1 {
			self.shares.push(Share {
				member_index: 1,
				data: shared_secret.to_owned(),
			});
		}

		let random_share_count = member_threshold - 2;

		for i in 0..random_share_count {
			self.shares.push(Share {
				member_index: i,
				data: fill_vec_rand(shared_secret.len()),
			});
		}

		let mut random_part = fill_vec_rand(shared_secret.len() - self.config.digest_length_bytes as usize);
		let mut digest = self.create_digest(&random_part, &shared_secret);
		digest.append(&mut random_part);
		
		let mut base_shares = self.shares.clone();
		base_shares.push(Share {
			member_index: self.config.digest_index,
			data: digest,
		});

		base_shares.push(Share {
			member_index: self.config.secret_index,
			data: shared_secret.to_owned()
		});
		
		Ok(())
	}

	fn create_digest(&self, random_data: &Vec<u8>, shared_secret: &Vec<u8>) -> Vec<u8>{
		let mut mac = HmacSha256::new_varkey(random_data).expect("HMAC error");
		mac.input(shared_secret);
		let mut result = [0u8; 32];
		result.copy_from_slice(mac.result().code().as_slice());
		let mut ret_vec = result.to_vec();
		ret_vec.split_off(4);
		ret_vec
	}
}

// fill a u8 vec with n bytes of random data
fn fill_vec_rand(n: usize) -> Vec<u8> {
	let mut v = vec![];
	for _ in 0 .. n {
		v.push(thread_rng().gen());
	}
	v
}

#[cfg(test)]
mod tests {
	use super::*;
	#[test]
	fn it_works() -> Result<(), error::Error> {
		let config = ShamirMnemonicConfig::default();
		let secret = fill_vec_rand(32);
		let mut sm = ShamirMnemonic::new(&config)?;
		sm.split_secret(4, 4, &secret)?;
		Ok(())
	}
}
