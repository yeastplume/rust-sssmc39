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

//! Master secret encryption

use crate::error::Error;

#[cfg(feature = "ring_pbkdf2")]
use ring::{digest, pbkdf2};
#[cfg(feature = "ring_pbkdf2")]
use std::num::NonZeroU32;
#[cfg(feature = "rust_crypto_pbkdf2")]
use pbkdf2::pbkdf2;
#[cfg(feature = "rust_crypto_pbkdf2")]
use sha2::Sha256;
#[cfg(feature = "rust_crypto_pbkdf2")]
use hmac::Hmac;


/// Config Struct
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MasterSecretEncConfig {
	/// The minimum number of iterations to use in PBKDF2
	pub min_iteration_count: u16,
	/// The number of rounds to use in the Feistel cipher
	pub round_count: u8,
	/// The customization string used in the RS1024 checksum and in the PBKDF2 salt
	pub customization_string: Vec<u8>,
}

impl Default for MasterSecretEncConfig {
	fn default() -> Self {
		let min_iteration_count = 10000;
		let round_count = 4;
		let customization_string = b"shamir".to_vec();

		MasterSecretEncConfig {
			min_iteration_count,
			round_count,
			customization_string,
		}
	}
}

impl MasterSecretEncConfig {
	/// Just use defaults for now
	pub fn new() -> Self {
		MasterSecretEncConfig {
			..Default::default()
		}
	}
}
/// Struct, so that config values are held
pub struct MasterSecretEnc {
	pub config: MasterSecretEncConfig,
}

impl Default for MasterSecretEnc {
	fn default() -> Self {
		MasterSecretEnc {
			config: MasterSecretEncConfig::new(),
		}
	}
}

impl MasterSecretEnc {
	/// Create a new encoder with all defaults
	pub fn new() -> Result<MasterSecretEnc, Error> {
		Ok(MasterSecretEnc {
			config: MasterSecretEncConfig::new(),
		})
	}

	pub fn encrypt(
		&self,
		master_secret: &[u8],
		passphrase: &str,
		iteration_exponent: u8,
		identifier: u16,
	) -> Vec<u8> {
		let mut l = master_secret.to_owned();
		let mut r = l.split_off(l.len() / 2);
		let salt = self.get_salt(identifier);
		for i in 0..self.config.round_count {
			// TODO This can be implemented without so much cloning
			let tmp_r = r.clone();
			r = self.xor(
				&l,
				&self.round_function(i, passphrase, iteration_exponent, &salt, &r),
			);
			l = tmp_r;
		}
		r.append(&mut l);
		r
	}

	pub fn decrypt(
		&self,
		enc_master_secret: &[u8],
		passphrase: &str,
		iteration_exponent: u8,
		identifier: u16,
	) -> Vec<u8> {
		let mut l = enc_master_secret.to_owned();
		let mut r = l.split_off(l.len() / 2);
		let salt = self.get_salt(identifier);
		for i in (0..self.config.round_count).rev() {
			// TODO This can be implemented without so much cloning
			let tmp_r = r.clone();
			r = self.xor(
				&l,
				&self.round_function(i, passphrase, iteration_exponent, &salt, &r),
			);
			l = tmp_r;
		}
		r.append(&mut l);
		r
	}

	fn get_salt(&self, identifier: u16) -> Vec<u8> {
		let mut retval = self.config.customization_string.clone();
		retval.append(&mut identifier.to_be_bytes().to_vec());
		retval
	}

	/// the round function used internally by the Feistel cipher
	fn round_function(
		&self,
		i: u8,
		passphrase: &str,
		e: u8,
		salt: &[u8],
		r: &[u8],
	) -> Vec<u8> {
		let iterations = (self.config.min_iteration_count << e) / u16::from(self.config.round_count);
		let out_length = r.len();
		let mut salt = salt.to_owned();
		let mut r = r.to_owned();
		salt.append(&mut r);
		let mut password = vec![i];
		password.append(&mut passphrase.as_bytes().to_vec());
		self.pbkdf2_derive(u32::from(iterations), &salt, &password, out_length)
	}
	#[cfg(feature = "rust_crypto_pbkdf2")]
	fn pbkdf2_derive(&self, iterations: u32, salt: &[u8], password: &[u8], out_length: usize) -> Vec<u8> {
		let mut out = vec![0; out_length];
		pbkdf2::<Hmac<Sha256>>(
			password,
			salt,
			iterations as usize,
			&mut out,
		);
		out
	}

	// Ring implementation of round function
	#[cfg(feature = "ring_pbkdf2")]
	fn pbkdf2_derive(&self, iterations: u32, salt: &[u8], password: &[u8], out_length: usize) -> Vec<u8> {
		let mut out = vec![0; out_length];
		pbkdf2::derive(
			&digest::SHA256,
			NonZeroU32::new(iterations as u32).unwrap(),
			salt,
			password,
			&mut out,
		);
		out
	}

	// xor values in both arrays, up to length of b
	fn xor(&self, a: &[u8], b: &[u8]) -> Vec<u8> {
		let mut retval = vec![0; b.len()];
		for i in 0..b.len() {
			retval[i] = a[i] ^ b[i];
		}
		retval
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use rand::{thread_rng, Rng};

	use crate::error::Error;

	fn enc_dec_test_impl(secret: Vec<u8>, passphrase: &str, identifier: u16) {
		let enc = MasterSecretEnc::default();
		println!("master_secret: {:?}", secret);
		let encrypted_secret = enc.encrypt(&secret, passphrase, 0, identifier);
		println!("encrypted_secret: {:?}", encrypted_secret);
		let decrypted_secret = enc.decrypt(&encrypted_secret, passphrase, 0, identifier);
		println!("decrypted_secret: {:?}", decrypted_secret);
		assert_eq!(secret, decrypted_secret);
	}

	#[test]
	fn master_enc_dec() -> Result<(), Error> {
		// from test vector
		let s = b"\x0c\x94\x90\xbcn\xd6\xbc\xbf\xac>\xbe}\xeeV\xf2P".to_vec();
		enc_dec_test_impl(s.to_vec(), "", 7470);
		// now some random 16 byte secrets
		for _ in 0..20 {
			let s: [u8; 16] = thread_rng().gen();
			let id: u16 = thread_rng().gen();
			enc_dec_test_impl(s.to_vec(), "", id);
		}
		// now some random 32 byte secrets
		for _ in 0..20 {
			let s: [u8; 32] = thread_rng().gen();
			let id: u16 = thread_rng().gen();
			enc_dec_test_impl(s.to_vec(), "", id);
		}
		// now some random 12 byte secrets
		for _ in 0..10 {
			let s: [u8; 12] = thread_rng().gen();
			let id: u16 = thread_rng().gen();
			enc_dec_test_impl(s.to_vec(), "", id);
		}
		// now some random 32 byte secrets with password
		for _ in 0..10 {
			let s: [u8; 12] = thread_rng().gen();
			let id: u16 = thread_rng().gen();
			enc_dec_test_impl(s.to_vec(), "pebkac", id);
		}

		Ok(())
	}
}
