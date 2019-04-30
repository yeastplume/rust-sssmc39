// Copyright 2019 ???
//
// TODO: LICENSE TEXT
//
//

//! Reid-Solomon code over GF(1024)

use crate::error::{Error, ErrorKind};

const GEN: [u32; 10] = [
	0xe0e040, 0x1c1c080, 0x3838100, 0x7070200, 0xe0e0009, 0x1c0c2412, 0x38086c24, 0x3090fc48,
	0x21b1f890, 0x3f3f120,
];

/// values intepreted as a list of 10 bit integers
fn polymod(values: &Vec<u32>) -> u32 {
	let mut chk = 1;
	let mut b: u32;
	for v in values {
		b = chk >> 20;
		chk = (chk & 0xfffff) << 10 ^ v;
		for i in 0..10 {
			if (b >> i) & 1 == 1 {
				chk ^= GEN[i];
			}
		}
	}
	chk
}

pub fn create_checksum(
	custom_string: &Vec<u8>,
	data: &Vec<u32>,
	checksum_length_words: u8,
) -> Vec<u32> {
	let mut values: Vec<u32> = custom_string.iter().map(|d| *d as u32).collect();
	for e in data {
		values.push(e.to_owned());
	}
	for _ in 0..checksum_length_words {
		values.push(0);
	}
	let polymod = polymod(&values) ^ 1;
	let mut retval = vec![];
	for i in 0..checksum_length_words as usize {
		retval.push(polymod >> 10 * (2 - i) & 1023);
	}
	retval
}

pub fn verify_checksum(custom_string: &Vec<u8>, data: &Vec<u32>) -> Result<(), Error> {
	let mut values: Vec<u32> = custom_string.iter().map(|d| *d as u32).collect();
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
		for i in 0..3 {
			test_vec.push(checksum[i]);
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
		for i in 0..3 {
			test_vec.push(checksum[i]);
		}
		verify_checksum(&b"shamir".to_vec(), &test_vec)?;
		assert!(verify_checksum(&b"fhamir".to_vec(), &test_vec).is_err());
		test_vec[1] = 99;
		assert!(verify_checksum(&b"shamir".to_vec(), &test_vec).is_err());

		Ok(())
	}
}
