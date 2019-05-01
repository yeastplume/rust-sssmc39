// Copyright 2019 ???
//
// TODO: LICENSE TEXT
//

mod config;
mod error;
mod field;
mod share;
mod util;

#[macro_use]
extern crate lazy_static;

use error::{Error, ErrorKind};
use rand::{thread_rng, Rng};

use hmac::{Hmac, Mac};
use sha2::Sha256;

use field::gf256::Gf256;
use field::lagrange;

use config::ShamirMnemonicConfig;
use share::Share;

use std::fmt;

// Create alias for HMAC-SHA256
type HmacSha256 = Hmac<Sha256>;

/// Struct for returned shares
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupShare {
	/// Group id
	pub group_id: u16,
	/// iteration exponent
	pub iteration_exponent: u8,
	/// group index
	pub group_index: u8,
	/// group threshold
	pub group_threshold: u8,
	/// number of group shares
	pub group_count: u8,
	/// member threshold:
	pub member_threshold: u8,
	/// Member shares for the group
	pub member_shares: Vec<Share>,
}

impl fmt::Display for GroupShare {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		writeln!(f, "Group {} of {} - {} of {} shares required: ", 
			self.group_index + 1,
			self.group_count,
			self.member_threshold,
			self.member_shares.len())?;
		for s in &self.member_shares {
			for w in s.to_mnemonic().unwrap() {
				write!(f, "{} ", w)?;
			}
			writeln!(f)?;
		}
		Ok(())
	}
}

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
		identifier: u16,
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
			s.identifier = identifier;
			s.member_index = 0;
			s.member_threshold = threshold;
			s.share_value = shared_secret.to_owned();
			shares.push(s);
			return Ok(shares);
		}

		let random_share_count = threshold - 2;

		for i in 0..random_share_count {
			let mut s = Share::new(&self.config)?;
			s.member_index = i;
			s.identifier = identifier;
			s.member_threshold = threshold;
			s.share_value = fill_vec_rand(shared_secret.len());
			shares.push(s);
		}

		let random_part =
			fill_vec_rand(shared_secret.len() - self.config.digest_length_bytes as usize);
		let mut digest = self.create_digest(&random_part.to_vec(), &shared_secret);
		digest.append(&mut random_part.to_vec());

		let mut base_shares = shares.clone();
		let mut s = Share::new(&self.config)?;
		s.identifier = identifier;
		s.member_index = self.config.digest_index;
		s.member_threshold = threshold;
		s.share_value = digest;
		base_shares.push(s);

		let mut s = Share::new(&self.config)?;
		s.identifier = identifier;
		s.member_index = self.config.secret_index;
		s.member_threshold = threshold;
		s.share_value = shared_secret.to_owned();
		base_shares.push(s);

		for i in random_share_count..share_count {
			let mut r = self.interpolate(&base_shares, i)?;
			r.identifier = identifier;
			r.member_index = i;
			r.member_threshold = threshold;
			shares.push(r);
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

	/// Split a master secret into mnemonic shares
	/// group_threshold: The number of groups required to reconstruct the master secret
	/// groups: A list of (member_threshold, member_count) pairs for each group, where member_count 
	/// is the number of shares to generate for the group and member_threshold is the number of 
	/// members required to reconstruct the group secret.
	/// master_secret: The master secret to split.
	/// passphrase: The passphrase used to encrypt the master secret.
	/// iteration_exponent: The iteration exponent.
	/// return: List of mnemonics.
	pub fn generate_mnemonics(&self, 
		group_threshold: u8,
		groups: &Vec<(u8, u8)>,
		master_secret: &Vec<u8>,
		passphrase: &str,
		iteration_exponent: u8) -> Result<Vec<GroupShare>, Error> {

		let identifier = self.generate_random_identifier();

		if master_secret.len() * 8 < self.config.min_strength_bits as usize {
				return Err(ErrorKind::Value(format!(
				"The length of the master secret ({} bytes) must be at least {} bytes.",
				master_secret.len(),
				(self.config.min_strength_bits as f64 / 8f64).ceil(),
			)))?;
		}

		if master_secret.len() % 2 != 0 {
				return Err(ErrorKind::Value(format!(
				"The length of the master secret in bytes must be an even number",
			)))?;
		}

		if group_threshold as usize > groups.len() {
				return Err(ErrorKind::Value(format!(
				"The requested group threshold ({}) must not exceed the number of groups ({}).",
				group_threshold,
				groups.len()
			)))?;
		}

		let encoder = util::encrypt::MasterSecretEnc::new(
			self.config.round_count,
			self.config.min_iteration_count,
			&self.config.customization_string,
		)?;

		let encrypted_master_secret = encoder.encrypt(
			master_secret,
			passphrase,
			iteration_exponent,
			identifier);

		let group_shares = self.split_secret(identifier, group_threshold, groups.len() as u8, &encrypted_master_secret)?;
		
		let mut retval: Vec<GroupShare> = vec![];

		let gs_len = group_shares.len();
		for (i, mut elem) in group_shares.into_iter().enumerate() {
			elem.group_index = i as u8;
			elem.group_threshold = group_threshold;
			elem.group_count = gs_len as u8;
			let (member_threshold, member_count) = groups[i];
			let member_shares = self.split_secret(identifier, member_threshold, member_count, &elem.share_value)?;
			let member_shares = member_shares.into_iter()
				.map(|s| {
					let mut r = s.clone();
					r.group_index = i as u8;
					r.group_threshold = group_threshold;
					r.group_count = gs_len as u8;
					r
				})
				.collect();
			
			retval.push(GroupShare {
				group_id: identifier,
				iteration_exponent: iteration_exponent,
				group_index: i as u8,
				group_threshold: group_threshold,
				group_count: gs_len as u8,
				member_threshold: member_threshold,
				member_shares,
			});
		}

		Ok(retval)
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

	fn generate_random_identifier(&self) -> u16 {
		let retval: u16 = thread_rng().gen();
		retval & ((1 << self.config.id_length_bits) - 1)
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
		let mut shares = sm.split_secret(0, threshold, total_shares, &secret)?;
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

	#[test]
	fn generate_mnemonics() -> Result<(), error::Error> {
		let sm = ShamirMnemonic::new(None);
    let master_secret = b"\x0c\x94\x90\xbcn\xd6\xbc\xbf\xac>\xbe}\xeeV\xf2P".to_vec();
		let mns = sm.generate_mnemonics(
			2,
			&vec![(3, 5), (4, 5)],
			&master_secret,
			"",
			0)?;

		for s in mns {
			println!("{}", s);
		}

		Ok(())

	}
}
