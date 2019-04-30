// Copyright 2019 ???
//
// TODO: LICENSE TEXT
//

//! Definition of a share, as well as functions to
//! convert it to and from a given wordlist

use crate::config::ShamirMnemonicConfig;
use crate::error::{Error, ErrorKind};
use crate::util::bitpacker::BitPacker;
use crate::util::rs1024;

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
	pub fn to_mnemonic(&self) -> Result<Vec<String>, Error> {
		let padding_bit_count = self.config.radix_bits
			- (self.share_value.len() * 8 % self.config.radix_bits as usize) as u8;
		let mut bp = BitPacker::new();

		bp.append_u16(self.identifier, 15)?;
		bp.append_u8(self.iteration_exponent, 5)?;
		bp.append_u8(self.group_index, 4)?;
		bp.append_u8(self.group_threshold - 1, 4)?;
		bp.append_u8(self.group_count - 1, 4)?;
		bp.append_u8(self.member_index, 4)?;
		bp.append_u8(self.member_threshold - 1, 4)?;
		bp.append_padding(padding_bit_count);
		bp.append_vec_u8(&self.share_value)?;

		if bp.len() % self.config.radix_bits as usize != 0 {
			return Err(ErrorKind::Mneumonic(format!(
				"Incorrect share bit length. Must be a multiple of {}, actual length: {}",
				self.config.radix_bits,
				bp.len(),
			)))?;
		}

		// Create checksum
		let mut sum_data: Vec<u32> = vec![];
		for i in (0..bp.len()).step_by(self.config.radix_bits as usize) {
			sum_data.push(bp.get_u32(i, self.config.radix_bits as usize)?);
		}

		let mut checksum = rs1024::create_checksum(
			&self.config.customization_string,
			&sum_data,
			self.config.checksum_length_words,
		);

		sum_data.append(&mut checksum);

		Ok(sum_data
			.iter()
			.map(|d| WORDLIST[*d as usize].to_owned())
			.collect())
	}

	/// convert mnemonic back to share
	pub fn from_mnemonic(config: &ShamirMnemonicConfig, mn: &Vec<String>) -> Result<Self, Error> {
		if mn.len() < config.min_mnemonic_length_words as usize {
			return Err(ErrorKind::Mneumonic(format!(
				"Invalid mnemonic length. The length of each mnemonic muse be at least {} words.",
				config.min_mnemonic_length_words,
			)))?;
		}
		let mut bp = BitPacker::new();
		for s in mn {
			bp.append_u16(WORD_INDEX_MAP[s] as u16, config.radix_bits)?;
		}

		let mut sum_data: Vec<u32> = vec![];
		for i in (0..bp.len()).step_by(config.radix_bits as usize) {
			sum_data.push(bp.get_u32(i, config.radix_bits as usize)?);
		}

		if (config.radix_bits as usize * (sum_data.len() - config.metadata_length_words as usize))
			% 16 > 8
		{
			return Err(ErrorKind::Mneumonic(format!("Invalid mnemonic length.",)))?;
		}
		rs1024::verify_checksum(&config.customization_string, &sum_data)?;

		let mut ret_share = Share::new(config)?;

		//TODO: iterator on bitpacker
		ret_share.identifier = bp.get_u16(0, 15)?;
		ret_share.iteration_exponent = bp.get_u8(15, 5)?;
		ret_share.group_index = bp.get_u8(20, 4)?;
		ret_share.group_threshold = bp.get_u8(24, 4)? + 1;
		ret_share.group_count = bp.get_u8(28, 4)? + 1;
		ret_share.member_index = bp.get_u8(32, 4)?;
		ret_share.member_threshold = bp.get_u8(36, 4)? + 1;

		if ret_share.group_count < ret_share.group_threshold {
			return Err(ErrorKind::Mneumonic(format!(
				"Invalid mnemonic. Group threshold cannot be greater than group count.",
			)))?;
		}

		// remove padding and recover data
		bp.split_out(
			40,
			bp.len() - config.radix_bits as usize * config.checksum_length_words as usize,
		);
		bp.remove_padding(bp.len() % 8);

		ret_share.share_value = bp.get_vec_u8(0, bp.len() / 8)?;

		Ok(ret_share)
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	use crate::error::Error;

	#[test]
	fn share_to_mnemonic() -> Result<(), Error> {
		// Test vectors taken from python reference implementation
		let expected_res: Vec<String> = vec![
			"phantom".into(),
			"branch".into(),
			"academic".into(),
			"axle".into(),
			"ceramic".into(),
			"alien".into(),
			"domain".into(),
			"alive".into(),
			"deadline".into(),
			"gray".into(),
			"walnut".into(),
			"spend".into(),
			"echo".into(),
			"amount".into(),
			"squeeze".into(),
			"woman".into(),
			"squeeze".into(),
			"welfare".into(),
			"filter".into(),
			"frequent".into(),
		];
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
		println!("orig share: {:?}", share);
		let m = share.to_mnemonic()?;
		println!("m: {:?}", m);
		assert_eq!(expected_res, m);

		let dec_share = Share::from_mnemonic(&ShamirMnemonicConfig::new(), &m)?;
		println!("decoded share: {:?}", dec_share);
		assert_eq!(share, dec_share);
		Ok(())
	}
}
