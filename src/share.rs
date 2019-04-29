// Copyright 2019 ???
//
// TODO: LICENSE TEXT
//

//! Definition of a share, as well as functions to
//! convert it to and from a given wordlist

use crate::config::ShamirMnemonicConfig;
use crate::error::{Error, ErrorKind};
use crate::util::bitpacker::BitPacker;

use std::collections::HashMap;

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

/// Main definition of a share and its mneumonic serialization
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
	/// configuration values
	config: ShamirMnemonicConfig,
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
			config: ShamirMnemonicConfig::new(),
		}
	}
}

impl Share {
	/// Create a new share with defaults
	pub fn new(config: &ShamirMnemonicConfig) -> Result<Share, Error> {
		if WORDLIST.len() != config.radix as usize {
			return Err(ErrorKind::Config(format!(
				"The wordlist should contain {} words, but it contains {} words.",
				config.radix,
				WORDLIST.len()
			)))?;
		}
		Ok(Share {
			config: config.to_owned(),
			..Default::default()
		})
	}

	/// Convert share data to a share mnemonic
	pub fn to_mnemonic(&self, radix_bits: u8) -> Result<Vec<u8>, Error> {
		let retval = vec![];
		let padding_bit_count =
			radix_bits - (self.share_value.len() * 8 % radix_bits as usize) as u8;
		println!("padding bit count: {}", padding_bit_count);
		let mut bv = BitPacker::new();

		bv.append_u16(self.identifier, 15)?;
		bv.append_u8(self.iteration_exponent, 5)?;
		bv.append_u8(self.group_index, 4)?;
		bv.append_u8(self.group_threshold, 4)?;
		bv.append_u8(self.group_count, 4)?;
		bv.append_u8(self.member_index, 4)?;
		bv.append_u8(self.member_threshold, 4)?;
		bv.append_padding(padding_bit_count);
		bv.append_vec_u8(&self.share_value)?;

		println!("BV: {:?}", bv);
		println!("bv.len(): {:?}", bv.len());

		Ok(retval)
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	use crate::error::Error;

	#[test]
	fn share_to_mnemonic() -> Result<(), Error> {
		// Test vectors taken from python reference implementation
		let expected_res =
			"phantom branch academic axle ceramic alien domain alive \
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
		let res = share.to_mnemonic(10)?;
		Ok(())
	}
}
