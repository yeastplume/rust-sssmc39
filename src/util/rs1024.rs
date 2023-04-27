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

//! Reid-Solomon code over GF(1024)

use crate::error::{Error, ErrorKind};

const GEN: [u32; 10] = [
	0x00e0_e040,
	0x1c1_c080,
	0x0383_8100,
	0x0707_0200,
	0xe0e_0009,
	0x1c0c_2412,
	0x3808_6c24,
	0x3090_fc48,
	0x21b1_f890,
	0x03f3_f120,
];

/// values intepreted as a list of 10 bit integers
fn polymod(values: &[u32]) -> u32 {
	let mut chk = 1;
	let mut b: u32;
	for v in values {
		b = chk >> 20;
		chk = (chk & 0xfffff) << 10 ^ v;
		for (i, item) in GEN.iter().enumerate() {
			if (b >> i) & 1 == 1 {
				chk ^= *item;
			}
		}
	}
	chk
}

pub fn create_checksum(custom_string: &[u8], data: &[u32], checksum_length_words: u8) -> Vec<u32> {
	let mut values: Vec<u32> = custom_string.iter().map(|d| u32::from(*d)).collect();
	for e in data {
		values.push(e.to_owned());
	}
	values.append(&mut vec![0; checksum_length_words as usize]);
	let polymod = polymod(&values) ^ 1;
	let mut retval = vec![];
	for i in 0..checksum_length_words as usize {
		retval.push(polymod >> (10 * (2 - i)) & 1023);
	}
	retval
}

pub fn verify_checksum(custom_string: &[u8], data: &[u32]) -> Result<(), Error> {
	let mut values: Vec<u32> = custom_string.iter().map(|d| u32::from(*d)).collect();
	for e in data {
		values.push(e.to_owned());
	}
	if polymod(&values) != 1 {
		return Err(ErrorKind::Config(format!(
			"Error verifying checksum: {:?}",
			data,
		)))?;
	}
	Ok(())
}

#[cfg(test)]
mod tests {
	use super::*;

	use crate::error::Error;

	#[test]
	fn checksum() -> Result<(), Error> {
		let mut test_vec = vec![
			663, 96, 0, 66, 132, 27, 234, 28, 191, 405, 992, 848, 257, 36, 858, 1012, 858,
		];
		let expected = vec![1001, 340, 369];
		let checksum = create_checksum(&b"shamir".to_vec(), &test_vec, 3);
		println!("Testvec: {:?}", test_vec);
		assert_eq!(checksum, expected);
		for i in checksum.iter().take(3) {
			test_vec.push(*i);
		}
		verify_checksum(&b"shamir".to_vec(), &test_vec)?;
		assert!(verify_checksum(&b"fhamir".to_vec(), &test_vec).is_err());
		test_vec[0] = 23;
		assert!(verify_checksum(&b"shamir".to_vec(), &test_vec).is_err());
		let mut test_vec = vec![
			663, 96, 0, 66, 177, 310, 288, 156, 827, 77, 232, 34, 965, 772, 962, 966, 754,
		];
		let expected = vec![247, 29, 757];
		let checksum = create_checksum(&b"shamir".to_vec(), &test_vec, 3);
		println!("Testvec: {:?}", test_vec);
		assert_eq!(checksum, expected);
		for i in checksum.iter().take(3) {
			test_vec.push(*i);
		}
		verify_checksum(&b"shamir".to_vec(), &test_vec)?;
		assert!(verify_checksum(&b"fhamir".to_vec(), &test_vec).is_err());
		test_vec[1] = 99;
		assert!(verify_checksum(&b"shamir".to_vec(), &test_vec).is_err());

		Ok(())
	}
}
