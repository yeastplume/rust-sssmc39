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
use rand::{thread_rng, Rng};

use hmac::{Hmac, Mac};
use sha2::Sha256;
use bitvec::BitVec;

use math::gf256::Gf256;
use math::lagrange;

// Constants

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
	/// Random 15 bit value which is the same for all shares and is used to verify
	/// that the shares belong together; it is also used as salt in the encryption
	/// of the master secret. (15 bits)
	pub identifier: u16,
	/// Indicates the total number of iterations to be used in PBKDF2. The number of
	/// iterations is calculated as 10000x2^e. (5 bits)
	pub iteration_exponent: u8,
	/// The x value of the group share (4 bits)
	pub group_index: u8,
	/// indicates how many group shares are needed to reconstruct the master secret.
	/// The actual value is endoded as Gt = GT - 1, so a value of 0 indicates that a
	/// single group share is needed (GT = 1), a value of 1 indicates that two group shares
	/// are needed (GT = 2) etc. (4 bits)
	pub group_threshold: u8,
	/// indicates the total number of groups. The actual value is encoded as g = G - 1
	/// (4 bits)
	pub group_count: u8,
	/// Member index, or x value of the member share in the given group (4 bits)
	pub member_index: u8,
	/// indicates how many member shares are needed to reconstruct the group share. The actual value
	/// is encoded as t = T − 1. (4 bits)
	pub member_threshold: u8,
	/// corresponds to a list of the SSS part's fk(x) values 1 ≤ k ≤ n. Each fk(x) value is encoded
	/// as a string of eight bits in big-endian order. The concatenation of these bit strings is
	/// the share value. This value is left-padded with "0" bits so that the length of the padded
	/// share value in bits becomes the nearest multiple of 10. (padding + 8n bits)
	pub share_value: Vec<u8>,
	/// an RS1024 checksum of the data part of the share
	/// (that is id || e || GI || Gt || g || I || t || ps). The customization string (cs) of
	/// RS1024 is "shamir". (30 bits)
	pub checksum: u32,
}

impl Default for Share {
	fn default() -> Self {
		Share {
			identifier: 0,
			iteration_exponent: 0,
			group_index: 0,
			group_threshold: 0,
			group_count: 0,
			member_index: 0,
			member_threshold: 0,
			share_value: vec![],
			checksum: 0,
		}
	}
}

impl Share {
	/// Convert share data to a share mnemonic
	pub fn to_mnemonic(&self, radix_bits: u8) -> Result<Vec<u8>, Error> {
		let retval = vec![];
		let padding_bit_count = radix_bits - (self.share_value.len() * 8 % radix_bits as usize) as u8;
		println!("padding bit count: {}", padding_bit_count);
		let mut bv: BitVec = BitVec::new();

		Share::add_u16(&mut bv, self.identifier, 15)?;
		Share::add_u8(&mut bv, self.iteration_exponent, 5)?;
		Share::add_u8(&mut bv, self.group_index, 4)?;
		Share::add_u8(&mut bv, self.group_threshold, 4)?;
		Share::add_u8(&mut bv, self.group_count, 4)?;
		Share::add_u8(&mut bv, self.member_index, 4)?;
		Share::add_u8(&mut bv, self.member_threshold, 4)?;
		Share::add_padding(&mut bv, padding_bit_count);
		Share::add_vec_u8(&mut bv, &self.share_value)?;

		println!("BV: {:?}", bv);
		println!("bv.len(): {:?}", bv.len());

		Ok(retval)
	}

	fn add_padding(bv: &mut BitVec, num_bits: u8) {
		for _ in 0..num_bits {
			bv.push(false);
		}
	}

	fn add_vec_u8(bv: &mut BitVec, data: &Vec<u8>) -> Result<(), Error> {
		for i in 0..data.len() {
			Share::add_u8(bv, data[i], 8)?;
		}
		Ok(())
	}

	fn add_u16(bv: &mut BitVec, val: u16, num_bits: u8) -> Result<(), Error> {
		if num_bits > 16 {
			return Err(ErrorKind::BitVec(format!(
				"number of bits to pack must be <= 16",
			)))?;
		}
		for i in (0u8..num_bits).rev() {
			if val & 2u16.pow(i as u32) == 0 {
				bv.push(false);
			} else {
				bv.push(true);
			}
		}
		Ok(())
	}

	fn add_u8(bv: &mut BitVec, val: u8, num_bits: u8) -> Result<(), Error> {
		if num_bits > 8 {
			return Err(ErrorKind::BitVec(format!(
				"number of bits to pack must be <= 8",
			)))?;
		}
		for i in (0u8..num_bits).rev() {
			if val & 2u8.pow(i as u32) == 0 {
				bv.push(false);
			} else {
				bv.push(true);
			}
		}
		Ok(())
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
				share_value: shared_secret.to_owned(),
				..Default::default()
			});
			return Ok(shares);
		}

		let random_share_count = threshold - 2;

		for i in 0..random_share_count {
			shares.push(Share {
				member_index: i,
				share_value: fill_vec_rand(shared_secret.len()),
				..Default::default()
			});
		}

		let random_part =
			fill_vec_rand(shared_secret.len() - self.config.digest_length_bytes as usize);
		let mut digest = self.create_digest(&random_part.to_vec(), &shared_secret);
		digest.append(&mut random_part.to_vec());

		let mut base_shares = shares.clone();
		base_shares.push(Share {
			member_index: self.config.digest_index,
			share_value: digest,
			..Default::default()
		});

		base_shares.push(Share {
			member_index: self.config.secret_index,
			share_value: shared_secret.to_owned(),
			..Default::default()
		});

		for i in random_share_count..share_count {
			shares.push(ShamirMnemonic::interpolate(&base_shares, i)?);
		}

		Ok(shares)
	}

	/// recover a secret
	pub fn recover_secret(&self, shares: &Vec<Share>, threshold: u8) -> Result<Share, Error> {
		let shared_secret = ShamirMnemonic::interpolate(shares, self.config.secret_index)?;

		if threshold != 1 {
			self.check_digest(shares, &shared_secret)?;
		}

		Ok(shared_secret)
	}

	fn interpolate(shares: &Vec<Share>, x: u8) -> Result<Share, Error> {
		let x_coords: Vec<u8> = shares.iter().map(|s| s.member_index).collect();

		if x_coords.contains(&x) {
			for s in shares {
				if s.member_index == x {
					return Ok(Share {
						member_index: x,
						share_value: s.share_value.clone(),
						..Default::default()
					});
				}
			}
		}

		let share_value_lengths = shares[0].share_value.len();
		for s in shares {
			if s.share_value.len() != share_value_lengths {
				return Err(ErrorKind::Mneumonic(format!(
					"Invalid set of shares. All share values must have the same length",
				)))?;
			}
		}

		let mut ret_share = Share {
			member_index: x,
			..Default::default()
		};

		for i in 0..share_value_lengths {
			let points: Vec<(Gf256, Gf256)> = shares
				.iter()
				.map(|s| {
					(
						Gf256::from_byte(s.member_index),
						Gf256::from_byte(s.share_value[i]),
					)
				})
				.collect();
			let poly = lagrange::interpolate(&points);
			let y = poly.evaluate_at(Gf256::from_byte(x));
			ret_share.share_value.push(y.to_byte());
		}

		Ok(ret_share)
	}

	fn create_digest(&self, random_data: &Vec<u8>, shared_secret: &Vec<u8>) -> Vec<u8> {
		let mut mac = HmacSha256::new_varkey(random_data).expect("HMAC error");
		mac.input(shared_secret);
		let mut result = [0u8; 32];
		result.copy_from_slice(mac.result().code().as_slice());
		let mut ret_vec = result.to_vec();
		ret_vec.split_off(4);
		ret_vec
	}

	fn check_digest(&self, shares: &Vec<Share>, shared_secret: &Share) -> Result<(), Error> {
		let digest_share = ShamirMnemonic::interpolate(shares, self.config.digest_index)?;
		let mut digest = digest_share.share_value.clone();
		let random_part = digest.split_off(self.config.digest_length_bytes as usize);
		if digest != self.create_digest(&random_part, &shared_secret.share_value) {
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
	for _ in 0..n {
		v.push(thread_rng().gen());
	}
	v
}

#[cfg(test)]
mod tests {
	use super::*;

	// run split and recover given shares and thresholds, then check random combinations of threshold
	// shares reconstruct the secret
	fn split_recover_impl(
		sm: &ShamirMnemonic,
		secret_length_bytes: usize,
		threshold: u8,
		total_shares: u8,
	) -> Result<(), error::Error> {
		let secret = fill_vec_rand(secret_length_bytes);
		println!("Secret is: {:?}", secret);
		let mut shares = sm.split_secret(threshold, total_shares, &secret)?;
		println!("Shares: {:?}", shares);
		for _ in threshold..total_shares {
			let recovered_secret = sm.recover_secret(&shares, threshold)?;
			println!("Recovered secret is: {:?}", secret);
			assert_eq!(secret, recovered_secret.share_value);
			if threshold == 1 {
				return Ok(());
			}
			// randomly remove a share till we're at threshold
			let remove_index = thread_rng().gen_range(0, shares.len());
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

	#[test]
	fn share_to_mnemonic() -> Result<(), error::Error> {
		// Test vectors taken from python reference implementation
		let expected_res = "phantom branch academic axle ceramic alien domain alive \
		deadline gray walnut spend echo amount squeeze woman squeeze welfare filter frequent";
		let share = Share {
			identifier: 21219,
			iteration_exponent: 0,
			group_index: 0,
			group_threshold: 1,
			group_count: 1,
			member_index: 4,
			member_threshold: 3,
			share_value: b"\x84\x06\xce\xa0p\xbfe~\rA\x01\t5\xaf\xd3Z".to_vec(),
			..Default::default()
		};
		let config = ShamirMnemonicConfig::default();
		let res = share.to_mnemonic(config.radix_bits)?;
		Ok(())
	}
}
