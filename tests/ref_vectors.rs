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

//! Execution of Test vectors from SLIP-39
#[macro_use]
extern crate serde_derive;

use serde_json;

use sssmc39::{to_hex, from_hex};
use sssmc39::{generate_mnemonics, combine_mnemonics, Error, Share};

use rand::{thread_rng, Rng};

// fill a u8 vec with n bytes of random data
pub fn fill_vec_rand(n: usize) -> Vec<u8> {
	let mut v = vec![];
	for _ in 0..n {
		v.push(thread_rng().gen());
	}
	v
}

// test vector entry, for deser from reference json
#[derive(Serialize, Deserialize, Debug, Clone)]
struct TVEntry {
	// Metadata (test description)
	pub meta: String,
	// List of mnemonics
	pub mnemonics: Vec<String>,
	// Resulting master secret (decoding should fail if empty)
	pub master_secret: String,
}

impl TVEntry {
	// get mnemonics as Vec<Vec<String>>
	pub fn mnemonics_to_vecs(&self) -> Vec<Vec<String>> {
		let mut retvec = vec![];
		for mn in self.mnemonics.iter() {
			retvec.push(mn.split_whitespace().map(|s| s.into()).collect());
		}
		retvec
	}
	// master secret to u8
	pub fn master_secret_to_u8_vec(&self) -> Vec<u8> {
		if self.master_secret.len() == 0 {
			vec![]
		} else {
			from_hex(self.master_secret.clone()).unwrap()
		}
	}
}

fn test_json_vectors(input: &str) -> Result<(), Error> {
	let tv_list: Vec<TVEntry> = serde_json::from_str(input).unwrap();
	for tv in tv_list {
		let ref_ms = tv.master_secret_to_u8_vec();
		println!("TESTVECS: {:?}", tv.mnemonics_to_vecs());
		println!("MASTER SECRET: {:?}", ref_ms);
		let result = combine_mnemonics(&tv.mnemonics_to_vecs(), "TREZOR");
		if ref_ms.len() > 0 {
			if let Ok(returned_ms) = result {
				assert_eq!(ref_ms, returned_ms);
				println!("OK - passed");
			}
		} else {
			if !result.is_err() {
				println!("Result SHOULD HAVE FAILED - {:?}", result);

				assert!(result.is_err());
			} else {
				println!("{}", result.unwrap_err());
				println!("OK - should fail");
			}
		}
	}
	Ok(())
}

#[test]
fn test_vectors() -> Result<(), Error> {
	let src = include_str!("fixtures/vectors/vectors.json");
	test_json_vectors(src)
}

#[test]
fn create_test_vectors() -> Result<(), Error> {
	let mut output = vec![];
	for n in [16, 32].to_vec() {
		let description = format!("Valid mnemomic without sharing ({} bits)", 8*n);
		let secret = fill_vec_rand(n);
		let groups = generate_mnemonics(1, &[(1, 1)].to_vec(), &secret, "TREZOR", 0)?;
		output.push(TVEntry {
			meta: description,
			mnemonics: groups[0].mnemonic_list_flat()?,
			master_secret: to_hex(secret.clone()),
		});

		let description = format!("Mnemonic with invalid checksum ({} bits)", 8*n);
		let indices = groups[0].member_shares[0].to_u8_vec()?;
		let share = Share::from_u8_vec(&indices)?;
		
		/*output.push(TVEntry {
			meta: description,
			mnemonics: share.mnemonic_list_flat()?,
			master_secret: "".to_owned(),
		});*/
	}
	let output = serde_json::to_string_pretty(&output).unwrap();
	println!("{}", output);
	// and test them
	test_json_vectors(&output)
}
