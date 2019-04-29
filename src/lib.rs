// Copyright 2019 ???
//
// TODO: LICENSE TEXT
//

mod config;
mod error;
mod math;
mod share;
mod util;

#[macro_use]
extern crate lazy_static;

use error::{Error, ErrorKind};
use rand::{thread_rng, Rng};

use hmac::{Hmac, Mac};
use sha2::Sha256;

use math::gf256::Gf256;
use math::lagrange;

use config::ShamirMnemonicConfig;
use share::Share;

// Create alias for HMAC-SHA256
type HmacSha256 = Hmac<Sha256>;

/// Main Struct
pub struct ShamirMnemonic {
	/// Configuration values
	config: ShamirMnemonicConfig,
}

impl ShamirMnemonic {
	/// Create new
	pub fn new(config: Option<&ShamirMnemonicConfig>) -> ShamirMnemonic {
		ShamirMnemonic {
			config: match config {
				Some(c) => c.to_owned(),
				None => ShamirMnemonicConfig::new(),
			},
		}
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
			let mut s = Share::new(&self.config)?;
			s.member_index = 1;
			s.share_value = shared_secret.to_owned();
			shares.push(s);
			return Ok(shares);
		}

		let random_share_count = threshold - 2;

		for i in 0..random_share_count {
			let mut s = Share::new(&self.config)?;
			s.member_index = i;
			s.share_value = fill_vec_rand(shared_secret.len());
			shares.push(s);
		}

		let random_part =
			fill_vec_rand(shared_secret.len() - self.config.digest_length_bytes as usize);
		let mut digest = self.create_digest(&random_part.to_vec(), &shared_secret);
		digest.append(&mut random_part.to_vec());

		let mut base_shares = shares.clone();
		let mut s = Share::new(&self.config)?;
		s.member_index = self.config.digest_index;
		s.share_value = digest;
		base_shares.push(s);

		let mut s = Share::new(&self.config)?;
		s.member_index = self.config.secret_index;
		s.share_value = shared_secret.to_owned();
		base_shares.push(s);

		for i in random_share_count..share_count {
			shares.push(self.interpolate(&base_shares, i)?);
		}

		Ok(shares)
	}

	/// recover a secret
	pub fn recover_secret(&self, shares: &Vec<Share>, threshold: u8) -> Result<Share, Error> {
		let shared_secret = self.interpolate(shares, self.config.secret_index)?;

		if threshold != 1 {
			self.check_digest(shares, &shared_secret)?;
		}

		Ok(shared_secret)
	}

	fn interpolate(&self, shares: &Vec<Share>, x: u8) -> Result<Share, Error> {
		let x_coords: Vec<u8> = shares.iter().map(|s| s.member_index).collect();

		if x_coords.contains(&x) {
			for s in shares {
				if s.member_index == x {
					let mut s = Share::new(&self.config)?;
					s.member_index = x;
					s.share_value = s.share_value.clone();
					return Ok(s);
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

		let mut ret_share = Share::new(&self.config)?;
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
		let digest_share = self.interpolate(shares, self.config.digest_index)?;
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
		let sm = ShamirMnemonic::new(None);
		// test invalid inputs
		assert!(split_recover_impl(&sm, 14, 3, 5).is_err());
		assert!(split_recover_impl(&sm, 2047, 10, 12).is_err());
		assert!(split_recover_impl(&sm, 16, 0, 5).is_err());
		assert!(split_recover_impl(&sm, 16, 5, 3).is_err());
		assert!(split_recover_impl(&sm, 16, 5, 0).is_err());
		// test a range of thresholds
		for sc in 1..=sm.config.max_share_count {
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
