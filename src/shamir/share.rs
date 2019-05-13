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

//! Definition of a share, as well as functions to
//! convert it to and from a given wordlist

use crate::error::{Error, ErrorKind};
use crate::util::bitpacker::BitPacker;
use crate::util::rs1024;

use rand::{thread_rng, Rng};
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

/// Share-specific configuration values
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShareConfig {
	/// The length of the random Identifier in bits
	pub id_length_bits: u8,
	/// The number of words in the word list
	pub radix: u16,
	/// The length of the radix in bits
	pub radix_bits: u8,
	/// id exp length
	pub id_exp_length_words: u8,
	/// The customization string used in the RS1024 checksum and in the PBKDF2 salt
	pub customization_string: Vec<u8>,
	/// The length of the RS1024 checksum in words
	pub checksum_length_words: u8,
	/// The length of mnemonic is words without the share value
	pub metadata_length_words: u8,
	/// The minimum allowed length of the mnemonic in words
	pub min_mnemonic_length_words: u8,
	/// The length of the iteration exponent in bits
	pub iteration_exp_length_bits: u8,
	/// The minimum allowed entropy of the master secret
	pub min_strength_bits: u16,
}

impl Default for ShareConfig {
	fn default() -> Self {
		let radix_bits = 10;
		let id_length_bits = 15;
		let iteration_exp_length_bits = 5;
		let checksum_length_words = 3;
		let customization_string = b"shamir".to_vec();
		let min_strength_bits = 128;

		// derived values
		let radix = 2u16.pow(radix_bits as u32);
		let id_exp_length_words = (id_length_bits + iteration_exp_length_bits) / radix_bits;
		let metadata_length_words = id_exp_length_words + 2 + checksum_length_words;
		let min_mnemonic_length_words =
			metadata_length_words + (min_strength_bits as f64 / 10f64).ceil() as u8;

		ShareConfig {
			id_length_bits,
			radix,
			radix_bits,
			id_exp_length_words,
			customization_string,
			checksum_length_words,
			metadata_length_words,
			min_mnemonic_length_words,
			iteration_exp_length_bits,
			min_strength_bits,
		}
	}
}

impl ShareConfig {
	/// Just use defaults for now
	pub fn new() -> Self {
		ShareConfig {
			..Default::default()
		}
	}
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
	pub config: ShareConfig,
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
			config: ShareConfig::new(),
		}
	}
}

impl Share {
	/// Create a new share with defaults
	pub fn new() -> Result<Share, Error> {
		let mut s = Share::default();
		s.identifier = s.generate_random_identifier();
		if WORDLIST.len() != s.config.radix as usize {
			return Err(ErrorKind::Config(format!(
				"The wordlist should contain {} words, but it contains {} words.",
				s.config.radix,
				WORDLIST.len()
			)))?;
		}
		Ok(s)
	}

	/// convenience to create new from Mneumonic
	pub fn from_mnemonic(mn: &Vec<String>) -> Result<Self, Error> {
		let s = Share::new()?;
		s.from_mnemonic_impl(mn)
	}

	// create the packed bit array
	fn pack_bits(&self) -> Result<BitPacker, Error> {
		let padding_bit_count = self.config.radix_bits
			- (self.share_value.len() * 8 % self.config.radix_bits as usize) as u8;
		let mut bp = BitPacker::new();

		bp.append_u16(self.identifier, self.config.id_length_bits)?;
		bp.append_u8(
			self.iteration_exponent,
			self.config.iteration_exp_length_bits,
		)?;
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

		let checksum = rs1024::create_checksum(
			&self.config.customization_string,
			&sum_data,
			self.config.checksum_length_words,
		);

		for c in checksum {
			bp.append_u32(c, self.config.radix_bits)?;
		}

		Ok(bp)
	}

	/// Convert share data to a share mnemonic
	pub fn to_mnemonic(&self) -> Result<Vec<String>, Error> {
		let bp = self.pack_bits()?;

		// Read bits as u32 vec
		let mut ret_vec: Vec<u32> = vec![];
		for i in (0..bp.len()).step_by(self.config.radix_bits as usize) {
			ret_vec.push(bp.get_u32(i, self.config.radix_bits as usize)?);
		}

		Ok(ret_vec
			.iter()
			.map(|d| WORDLIST[*d as usize].to_owned())
			.collect())
	}

	/// Convert share data to u8 vec
	pub fn to_u8_vec(&self) -> Result<Vec<u8>, Error> {

		let bp = self.pack_bits()?;

		// Read bits as u8 vec
		let mut ret_vec: Vec<u8> = vec![];
		for i in (0..bp.len()).step_by(8) {
			ret_vec.push(bp.get_u8(i, 8)?);
		}

		Ok(ret_vec)
	}

	/// convert mnemonic back to share
	fn from_mnemonic_impl(&self, mn: &Vec<String>) -> Result<Self, Error> {
		if mn.len() < self.config.min_mnemonic_length_words as usize {
			return Err(ErrorKind::Mneumonic(format!(
				"Invalid mnemonic length. The length of each mnemonic must be at least {} words.",
				self.config.min_mnemonic_length_words,
			)))?;
		}
		let mut bp = BitPacker::new();
		for s in mn {
			bp.append_u16(WORD_INDEX_MAP[s] as u16, self.config.radix_bits)?;
		}

		let mut sum_data: Vec<u32> = vec![];
		for i in (0..bp.len()).step_by(self.config.radix_bits as usize) {
			sum_data.push(bp.get_u32(i, self.config.radix_bits as usize)?);
		}

		if (self.config.radix_bits as usize
			* (sum_data.len() - self.config.metadata_length_words as usize))
			% 16 > 8
		{
			return Err(ErrorKind::Mneumonic(format!("Invalid mnemonic length.",)))?;
		}

		rs1024::verify_checksum(&self.config.customization_string, &sum_data)?;

		let mut ret_share = Share::new()?;

		//TODO: iterator on bitpacker
		ret_share.identifier = bp.get_u16(0, self.config.id_length_bits as usize)?;
		ret_share.iteration_exponent = bp.get_u8(
			self.config.id_length_bits as usize,
			self.config.iteration_exp_length_bits as usize,
		)?;
		ret_share.group_index = bp.get_u8(
			(self.config.id_length_bits + self.config.iteration_exp_length_bits) as usize,
			4,
		)?;
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
			bp.len() - self.config.radix_bits as usize * self.config.checksum_length_words as usize,
		);
		bp.remove_padding(bp.len() % 8)?;

		ret_share.share_value = bp.get_vec_u8(0, bp.len() / 8)?;

		Ok(ret_share)
	}

	fn generate_random_identifier(&self) -> u16 {
		let retval: u16 = thread_rng().gen();
		retval & ((1 << self.config.id_length_bits) - 1)
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

		let dec_share = Share::from_mnemonic(&m)?;
		println!("decoded share: {:?}", dec_share);
		assert_eq!(share, dec_share);
		Ok(())
	}
}
