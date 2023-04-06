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

use crate::error::{Error, ErrorKind};
use crate::shamir::Share;
use crate::util;

use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::field::gf256::Gf256;
use crate::field::lagrange;

// Create alias for HMAC-SHA256
type HmacSha256 = Hmac<Sha256>;

/// Share split configuration values
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SplitterConfig {
	/// The length of the random Identifier in bits
	// TODO: Redundant with ShareConfig value
	pub id_length_bits: u8,
	/// The maximum number of shares that can be created
	pub max_share_count: u8,
	/// The length of the digest of the shared secret in bytes
	pub digest_length_bytes: u8,
	/// The index of the share containing the shared secret
	pub secret_index: u8,
	/// The index of the share containing the digest of the shared secret
	pub digest_index: u8,
}

impl Default for SplitterConfig {
	fn default() -> Self {
		let id_length_bits = 15;
		let max_share_count = 16;
		let digest_length_bytes = 4;
		let secret_index = 255;
		let digest_index = 254;

		SplitterConfig {
			id_length_bits,
			max_share_count,
			digest_length_bytes,
			secret_index,
			digest_index,
		}
	}
}

impl SplitterConfig {
	/// Just use defaults for now
	pub fn new() -> Self {
		SplitterConfig {
			..Default::default()
		}
	}
}

/// Main Struct
pub struct Splitter {
	/// Configuration values
	config: SplitterConfig,
}

impl Splitter {
	/// Create new
	pub fn new(config: Option<&SplitterConfig>) -> Splitter {
		Splitter {
			config: match config {
				Some(c) => c.to_owned(),
				None => SplitterConfig::new(),
			},
		}
	}

	/// split secret
	/// member_threshold, share_count, shared_secret at least 128 bits and a multiple of 16
	/// returns shares
	pub fn split_secret(
		&self,
		proto_share: &Share,
		threshold: u8,
		share_count: u8,
		shared_secret: &[u8],
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
			return Err(ErrorKind::Argument(
				"Secret must be at least 16 bytes in length and a multiple of 2".to_string(),
			))?;
		}

		let mut shares = vec![];
		// if the threshold is 1, then the digest of the shared secret is not used
		if threshold == 1 {
			for i in 0..share_count {
				let mut s = proto_share.clone();
				s.member_index = i;
				s.member_threshold = threshold;
				s.share_value = shared_secret.to_owned();
				shares.push(s);
			}
			return Ok(shares);
		}

		let random_share_count = threshold - 2;

		for i in 0..random_share_count {
			let mut s = proto_share.clone();
			s.member_index = i;
			s.member_threshold = threshold;
			s.share_value = util::fill_vec_rand(shared_secret.len());
			shares.push(s);
		}

		let random_part =
			util::fill_vec_rand(shared_secret.len() - self.config.digest_length_bytes as usize);
		let mut digest = self.create_digest(&random_part.to_vec(), shared_secret);
		digest.append(&mut random_part.to_vec());

		let mut base_shares = shares.clone();
		let mut s = proto_share.clone();
		s.member_index = self.config.digest_index;
		s.member_threshold = threshold;
		s.share_value = digest;
		base_shares.push(s);

		let mut s = proto_share.clone();
		s.member_index = self.config.secret_index;
		s.member_threshold = threshold;
		s.share_value = shared_secret.to_owned();
		base_shares.push(s);

		for i in random_share_count..share_count {
			let mut r = self.interpolate(&base_shares, i, proto_share)?;
			r.member_index = i;
			r.member_threshold = threshold;
			shares.push(r);
		}

		//self.check_digest(&shares, &shared_secret, &proto_share)?;

		Ok(shares)
	}

	/// recover a secret
	pub fn recover_secret(&self, shares: &[Share], threshold: u8) -> Result<Share, Error> {
		if shares.is_empty() {
			return Err(ErrorKind::Value("Share set must not be empty.".to_string()))?;
		}
		let mut proto_share = shares[0].clone();
		proto_share.share_value = vec![];

		let shared_secret = self.interpolate(shares, self.config.secret_index, &proto_share)?;

		if threshold != 1 {
			self.check_digest(shares, &shared_secret, &proto_share)?;
		}

		Ok(shared_secret)
	}

	fn interpolate(&self, shares: &[Share], x: u8, proto_share: &Share) -> Result<Share, Error> {
		let x_coords: Vec<u8> = shares.iter().map(|s| s.member_index).collect();

		if x_coords.contains(&x) {
			for s in shares {
				if s.member_index == x {
					let mut ret_s = proto_share.clone();
					ret_s.member_index = x;
					ret_s.share_value = s.share_value.clone();
					return Ok(ret_s);
				}
			}
		}

		let share_value_lengths = shares[0].share_value.len();
		for s in shares {
			if s.share_value.len() != share_value_lengths {
				return Err(ErrorKind::Mnemonic(
					"Invalid set of shares. All share values must have the same length".to_string(),
				))?;
			}
		}

		let mut ret_share = proto_share.clone();
		ret_share.member_index = x;

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

	fn create_digest(&self, random_data: &[u8], shared_secret: &[u8]) -> Vec<u8> {
		let mut mac = HmacSha256::new_varkey(random_data).expect("HMAC error");
		mac.input(shared_secret);
		let mut result = [0u8; 32];
		result.copy_from_slice(mac.result().code().as_slice());
		let mut ret_vec = result.to_vec();
		ret_vec.truncate(4);
		ret_vec
	}

	fn check_digest(
		&self,
		shares: &[Share],
		shared_secret: &Share,
		proto_share: &Share,
	) -> Result<(), Error> {
		let digest_share = self.interpolate(shares, self.config.digest_index, proto_share)?;
		let mut digest = digest_share.share_value;
		let random_part = digest.split_off(self.config.digest_length_bytes as usize);
		if digest != self.create_digest(&random_part, &shared_secret.share_value) {
			return Err(ErrorKind::Digest(
				"Invalid digest of the shared secret".to_string(),
			))?;
		}
		Ok(())
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use rand::{thread_rng, Rng};

	// run split and recover given shares and thresholds, then check random combinations of threshold
	// shares reconstruct the secret
	fn split_recover_impl(
		secret_length_bytes: usize,
		threshold: u8,
		total_shares: u8,
	) -> Result<(), Error> {
		let sp = Splitter::new(None);
		let secret = util::fill_vec_rand(secret_length_bytes);
		println!("Secret is: {:?}", secret);
		let proto_share = Share::new()?;
		let mut shares = sp.split_secret(&proto_share, threshold, total_shares, &secret)?;
		println!("Shares: {:?}", shares);
		for _ in threshold..total_shares {
			let recovered_secret = sp.recover_secret(&shares, threshold)?;
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
			assert!(sp.recover_secret(&shares, threshold).is_err());
		}
		Ok(())
	}

	#[test]
	fn split_recover() -> Result<(), Error> {
		// test invalid inputs
		assert!(split_recover_impl(14, 3, 5).is_err());
		assert!(split_recover_impl(2047, 10, 12).is_err());
		assert!(split_recover_impl(16, 0, 5).is_err());
		assert!(split_recover_impl(16, 5, 3).is_err());
		assert!(split_recover_impl(16, 5, 0).is_err());
		// test a range of thresholds
		let config = SplitterConfig::new();
		for sc in 1..=config.max_share_count {
			for t in 1..=sc {
				split_recover_impl(16, t, sc)?;
			}
		}
		// test a range of lengths
		for sl in (16..32).step_by(2) {
			split_recover_impl(sl, 3, 5)?;
			split_recover_impl(sl, 2, 3)?;
		}
		// test a couple of nice long lengths
		split_recover_impl(2048, 3, 5)?;
		split_recover_impl(4096, 10, 16)?;
		Ok(())
	}
}
