// Copyright 2019 ???
//
// TODO: LICENSE TEXT
//

mod error;
mod math;

use std::collections::HashMap;

#[macro_use]
extern crate lazy_static;

use error::{Error, ErrorKind};
use rand::{Rng, thread_rng};

use hmac::{Hmac, Mac};
use sha2::Sha256;

use math::gf256::Gf256;
use math::lagrange;


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
		})
	}

	/// split secret
	/// member_threshold, share_count, shared_secret at least 128 bits and a multiple of 16
	/// returns shares
	pub fn split_secret(
		&self,
		threshold: u8,
		share_count: u8,
		shared_secret: &Vec<u8>,
	) -> Result<Vec<Share>, Error> {
		if threshold == 0 || threshold > self.config.max_share_count {
			return Err(ErrorKind::Argument(format!(
				"Threshold must be between 1 and {}",
				self.config.max_share_count
			)))?;
		}
		if share_count < threshold || share_count > self.config.max_share_count {
			return Err(ErrorKind::Argument(format!(
				"Share count with given member threshold must be between {} and {}",
				threshold, self.config.max_share_count
			)))?;
		}
		if shared_secret.len() < 16 || shared_secret.len() % 2 != 0 {
			return Err(ErrorKind::Argument(format!(
				"Secret must be at least 16 bytes in length and a multiple of 2",
			)))?;
		}

		let mut shares = vec![];
		// if the threshold is 1, then the digest of the shared secret is not used
		if threshold == 1 {
			shares.push(Share {
				member_index: 1,
				data: shared_secret.to_owned(),
			});
			return Ok(shares);
		}

		let random_share_count = threshold - 2;

		for i in 0..random_share_count {
			shares.push(Share {
				member_index: i,
				data: fill_vec_rand(shared_secret.len()),
			});
		}

		let random_part = fill_vec_rand(shared_secret.len() - self.config.digest_length_bytes as usize);
		let mut digest = self.create_digest(&random_part.to_vec(), &shared_secret);
		digest.append(&mut random_part.to_vec());

		let mut base_shares = shares.clone();
		base_shares.push(Share {
			member_index: self.config.digest_index,
			data: digest,
		});

		base_shares.push(Share {
			member_index: self.config.secret_index,
			data: shared_secret.to_owned()
		});

		for i in random_share_count..share_count {
			shares.push(ShamirMnemonic::interpolate(&base_shares, i)?);
		}

		Ok(shares)
	}

	/// recover a secret
	pub fn recover_secret(&self, shares: &Vec<Share>, threshold:u8) -> Result<Share, Error> {
		let shared_secret = ShamirMnemonic::interpolate(shares, self.config.secret_index)?;

		if threshold != 1 {
			self.check_digest(shares, &shared_secret)?;
		}

		Ok(shared_secret)
	}

	fn interpolate(shares: &Vec<Share>, x: u8) -> Result<Share, Error> {
		let x_coords:Vec<u8> = shares.iter()
			.map(|s| s.member_index)
			.collect();

		if x_coords.contains(&x) {
			for s in shares {
				if s.member_index == x {
					return Ok(Share{member_index:x, data:s.data.clone()});
				}
			}
		}

		let share_value_lengths = shares[0].data.len();
		for s in shares {
			if s.data.len() != share_value_lengths {
				return Err(ErrorKind::Mneumonic(format!(
					"Invalid set of shares. All share values must have the same length",
				)))?;
			}
		}

		let mut ret_share = Share {
			member_index: x,
			data: vec![],
		};

		for i in 0..share_value_lengths {
			let points:Vec<(Gf256, Gf256)> = shares.iter()
				.map(|s| (Gf256::from_byte(s.member_index), Gf256::from_byte(s.data[i])))
				.collect();
			let poly = lagrange::interpolate(&points);
			let y = poly.evaluate_at(Gf256::from_byte(x));
			ret_share.data.push(y.to_byte());
		}

		Ok(ret_share)
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

	fn check_digest(&self, shares:&Vec<Share>, shared_secret: &Share) -> Result<(), Error> {
		let digest_share = ShamirMnemonic::interpolate(shares, self.config.digest_index)?;
		let mut digest = digest_share.data.clone();
		let random_part = digest.split_off(self.config.digest_length_bytes as usize);
		if digest != self.create_digest(&random_part, &shared_secret.data) {
			return Err(ErrorKind::Digest(format!(
				"Invalid digest of the shared secret",
			)))?;
		}
		Ok(())
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

	// run split and recover given shares and thresholds, then check random combinations of threshold
	// shares reconstruct the secret
	fn split_recover_impl(sm: &ShamirMnemonic, secret_length_bytes: usize, threshold: u8, total_shares: u8) -> Result<(), error::Error> {
		let secret = fill_vec_rand(secret_length_bytes);
		println!("Secret is: {:?}", secret);
		let mut shares = sm.split_secret(threshold, total_shares, &secret)?;
		println!("Shares: {:?}", shares);
		for _ in threshold..total_shares {
			let recovered_secret = sm.recover_secret(&shares, threshold)?;
			println!("Recovered secret is: {:?}", secret);
			assert_eq!(secret, recovered_secret.data);
			if threshold == 1 {
				return Ok(())
			}
			// randomly remove a share till we're at threshold
			let remove_index = thread_rng().gen_range(0,shares.len());
			shares.remove(remove_index);
		}
		// now remove one more, and recovery should fail
		if shares.len() > 1 {
			let remove_index = thread_rng().gen_range(0, shares.len());
			shares.remove(remove_index);
			assert!(sm.recover_secret(&shares, threshold).is_err());
		}
		Ok(())
	}

	#[test]
	fn split_recover() -> Result<(), error::Error> {
		let config = ShamirMnemonicConfig::default();
		let sm = ShamirMnemonic::new(&config)?;
		// test invalid inputs
		assert!(split_recover_impl(&sm, 14, 3, 5).is_err());
		assert!(split_recover_impl(&sm, 2047, 10, 12).is_err());
		assert!(split_recover_impl(&sm, 16, 0, 5).is_err());
		assert!(split_recover_impl(&sm, 16, 5, 3).is_err());
		assert!(split_recover_impl(&sm, 16, 5, 0).is_err());
		// test a range of thresholds
		for sc in 1..=config.max_share_count {
			for t in 1..=sc {
				split_recover_impl(&sm, 16, t, sc)?;
			}
		}
		// test a range of lengths
		for sl in (16..32).step_by(2) {
			split_recover_impl(&sm, sl, 3, 5)?;
			split_recover_impl(&sm, sl, 2, 3)?;
		}
		// test a couple of nice long lengths
		split_recover_impl(&sm, 2048, 3, 5)?;
		split_recover_impl(&sm, 4096, 10, 16)?;
		Ok(())
	}
}
