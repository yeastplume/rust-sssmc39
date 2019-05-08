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
use std::num::NonZeroU32;

use crate::error::Error;

use ring::{digest, pbkdf2};

/// Struct, so that config values are held
pub struct MasterSecretEnc {
	round_count: u8,
	min_iteration_count: u16,
	customization_string: Vec<u8>,
}

impl Default for MasterSecretEnc {
	fn default() -> Self {
		MasterSecretEnc {
			round_count: 4,
			min_iteration_count: 10000,
			customization_string: b"shamir".to_vec(),
		}
	}
}

impl MasterSecretEnc {
	/// Create a new encoder with all defaults
	pub fn new(
		round_count: u8,
		min_iteration_count: u16,
		customization_string: &Vec<u8>,
	) -> Result<MasterSecretEnc, Error> {
		Ok(MasterSecretEnc {
			round_count,
			min_iteration_count,
			customization_string: customization_string.to_owned(),
		})
	}

	pub fn encrypt(
		&self,
		master_secret: &Vec<u8>,
		passphrase: &str,
		iteration_exponent: u8,
		identifier: u16,
	) -> Vec<u8> {
		let mut l = master_secret.to_owned();
		let mut r = l.split_off(l.len() / 2);
		let salt = self.get_salt(identifier);
		for i in 0..self.round_count {
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
		enc_master_secret: &Vec<u8>,
		passphrase: &str,
		iteration_exponent: u8,
		identifier: u16,
	) -> Vec<u8> {
		let mut l = enc_master_secret.to_owned();
		let mut r = l.split_off(l.len() / 2);
		let salt = self.get_salt(identifier);
		for i in (0..self.round_count).rev() {
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
		let mut retval = self.customization_string.clone();
		retval.append(&mut identifier.to_be_bytes().to_vec());
		retval
	}

	/// the round function used internally by the Feistel cipher
	fn round_function(
		&self,
		i: u8,
		passphrase: &str,
		e: u8,
		salt: &Vec<u8>,
		r: &Vec<u8>,
	) -> Vec<u8> {
		let iterations = (self.min_iteration_count << e) / self.round_count as u16;
		let out_length = r.len();
		let mut salt = salt.clone();
		let mut r = r.clone();
		salt.append(&mut r);
		let mut password = vec![i];
		password.append(&mut passphrase.as_bytes().to_vec());
		let mut out = vec![0; out_length];
		pbkdf2::derive(
			&digest::SHA256,
			NonZeroU32::new(iterations as u32).unwrap(),
			&salt,
			&password,
			&mut out,
		);
		out
	}

	// xor values in both arrays, up to length of b
	fn xor(&self, a: &Vec<u8>, b: &Vec<u8>) -> Vec<u8> {
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
