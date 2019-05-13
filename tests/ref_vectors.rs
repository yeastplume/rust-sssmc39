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

use sssmc39::from_hex;
use sssmc39::{combine_mneumonics, Error};

// test vector entry, for deser from reference json
#[derive(Serialize, Deserialize, Debug, Clone)]
struct TVEntry {
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

#[test]
fn test_vectors() -> Result<(), Error> {
	let src = include_str!("fixtures/vectors/vectors.json");
	let tv_list: Vec<TVEntry> = serde_json::from_str(src).unwrap();
	for tv in tv_list {
		let ref_ms = tv.master_secret_to_u8_vec();
		println!("TESTVECS: {:?}", tv.mnemonics_to_vecs());
		println!("MASTER SECRET: {:?}", ref_ms);
		let result = combine_mneumonics(&tv.mnemonics_to_vecs(), "TREZOR");
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
