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

//! Functions and structs that specifically define the SLIPS-0039 scheme

use super::{Share, Splitter};
use crate::error::{Error, ErrorKind};
use crate::shamir::splitter::fill_vec_rand;


use std::collections::BTreeMap;
use std::fmt;

use crate::util;

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

impl Default for GroupShare {
	fn default() -> Self {
		GroupShare {
			group_id: 0,
			iteration_exponent: 0,
			group_index: 0,
			group_threshold: 0,
			group_count: 0,
			member_threshold: 0,
			member_shares: vec![],
		}
	}
}

impl fmt::Display for GroupShare {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		writeln!(
			f,
			"Group {} of {} - {} of {} shares required: ",
			self.group_index + 1,
			self.group_count,
			self.member_threshold,
			self.member_shares.len()
		)?;
		for s in &self.member_shares {
			for w in s.to_mnemonic().unwrap() {
				write!(f, "{} ", w)?;
			}
			writeln!(f)?;
		}
		Ok(())
	}
}

impl GroupShare {
	/// return list of mnemonics
	pub fn mnemonic_list(&self) -> Result<Vec<Vec<String>>, Error> {
		let mut ret_vec = vec![];
		for s in &self.member_shares {
			ret_vec.push(s.to_mnemonic()?);
		}
		Ok(ret_vec)
	}

	/// decode member shares to single share
	pub fn decode_shares(&mut self) -> Result<Share, Error> {
		let sp = Splitter::new(None);
		sp.recover_secret(&self.member_shares, self.member_threshold)
	}
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
pub fn generate_mneumonics(
	group_threshold: u8,
	groups: &Vec<(u8, u8)>,
	master_secret: &Vec<u8>,
	passphrase: &str,
	iteration_exponent: u8,
) -> Result<Vec<GroupShare>, Error> {
	// Generate a 'proto share' so to speak, with identifer generated and group data filled
	let mut proto_share = Share::new()?;
	proto_share.group_threshold = group_threshold;
	proto_share.group_count = groups.len() as u8;

	if master_secret.len() * 8 < proto_share.config.min_strength_bits as usize {
		return Err(ErrorKind::Value(format!(
			"The length of the master secret ({} bytes) must be at least {} bytes.",
			master_secret.len(),
			(proto_share.config.min_strength_bits as f64 / 8f64).ceil(),
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

	let encoder = util::encrypt::MasterSecretEnc::new()?;

	let encrypted_master_secret = encoder.encrypt(
		master_secret,
		passphrase,
		iteration_exponent,
		proto_share.identifier,
	);

	let sp = Splitter::new(None);

	let group_shares = sp.split_secret(
		&proto_share,
		group_threshold,
		groups.len() as u8,
		&encrypted_master_secret,
	)?;

	let mut retval: Vec<GroupShare> = vec![];

	let gs_len = group_shares.len();
	for (i, elem) in group_shares.into_iter().enumerate() {
		proto_share.group_index = i as u8;
		proto_share.group_threshold = group_threshold;
		proto_share.group_count = gs_len as u8;
		let (member_threshold, member_count) = groups[i];
		let member_shares = sp.split_secret(
			&proto_share,
			member_threshold,
			member_count,
			&elem.share_value,
		)?;
		retval.push(GroupShare {
			group_id: proto_share.identifier,
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

pub fn generate_mneumonics_random(
	group_threshold: u8,
	groups: &Vec<(u8, u8)>,
	strength_bits: u16,
	passphrase: &str,
	iteration_exponent: u8,
) -> Result<Vec<GroupShare>, Error> {
	let proto_share = Share::new()?;
	if strength_bits < proto_share.config.min_strength_bits {
		return Err(ErrorKind::Value(format!(
			"The requested strength of the master secret({} bits) must be at least {} bits.",
			strength_bits,
			proto_share.config.min_strength_bits,
		)))?;
	}
	if strength_bits % 16 != 0 {
		return Err(ErrorKind::Value(format!(
			"The requested strength of the master secret({} bits) must be a multiple of 16 bits.",
			strength_bits,
		)))?;
	}
	generate_mneumonics(group_threshold, groups, &fill_vec_rand(strength_bits as usize / 8), passphrase, iteration_exponent)
}

/// Combines mnemonic shares to obtain the master secret which was previously split using
/// Shamir's secret sharing scheme.
/// mnemonics: List of mnemonics.
/// passphrase: The passphrase used to encrypt the master secret.
/// return: The master secret.
pub fn combine_mneumonics(
	mnemonics: &Vec<Vec<String>>,
	passphrase: &str,
) -> Result<Vec<u8>, Error> {
	let group_shares = decode_mneumonics(mnemonics)?;
	let mut shares = vec![];
	for mut gs in group_shares {
		shares.push(gs.decode_shares()?);
	}
	let sp = Splitter::new(None);
	// restore proper member index for groups
	let shares = shares
		.into_iter()
		.map(|mut s| {
			s.member_index = s.group_index;
			s
		})
		.collect();
	let ems = sp.recover_secret(&shares, shares[0].group_threshold)?;
	let encoder = util::encrypt::MasterSecretEnc::new()?;
	let dms = encoder.decrypt(
		&ems.share_value,
		passphrase,
		ems.iteration_exponent,
		ems.identifier,
	);
	Ok(dms)
}

/// Decodes all Mneumonics to a list of shares and performs error checking
fn decode_mneumonics(mnemonics: &Vec<Vec<String>>) -> Result<Vec<GroupShare>, Error> {
	let mut shares = vec![];
	if mnemonics.len() == 0 {
		return Err(ErrorKind::Mneumonic(
			format!("List of mnemonics is empty.",),
		))?;
	}
	let check_len = mnemonics[0].len();
	for m in mnemonics {
		if m.len() != check_len {
			return Err(ErrorKind::Mneumonic(format!(
				"Invalid set of mnemonics. All mnemonics must have the same length.",
			)))?;
		}
		shares.push(Share::from_mnemonic(&m)?);
	}

	let check_share = shares[0].clone();
	for s in shares.iter() {
		if s.identifier != check_share.identifier
			|| s.iteration_exponent != check_share.iteration_exponent
		{
			return Err(ErrorKind::Mneumonic(format!(
				"Invalid set of mnemonics. All mnemonics must begin with the same {} words. \
				 (Identifier and iteration exponent must be the same).",
				s.config.id_exp_length_words,
			)))?;
		}
		if s.group_threshold != check_share.group_threshold {
			return Err(ErrorKind::Mneumonic(format!(
				"Invalid set of mnemonics. All mnemonics must have the same group threshold"
			)))?;
		}
		if s.group_count != check_share.group_count {
			return Err(ErrorKind::Mneumonic(format!(
				"Invalid set of mnemonics. All mnemonics must have the same group count"
			)))?;
		}
	}

	let mut group_index_map = BTreeMap::new();

	for s in shares {
		if !group_index_map.contains_key(&s.group_index) {
			let mut group_share = GroupShare::default();
			group_share.group_id = s.identifier;
			group_share.group_index = s.group_index;
			group_share.group_threshold = s.group_threshold;
			group_share.iteration_exponent = s.iteration_exponent;
			group_share.group_count = s.group_count;
			group_share.member_shares = vec![s.clone()];
			group_share.member_threshold = s.member_threshold;
			group_index_map.insert(group_share.group_index, group_share);
		} else {
			let e = group_index_map.get_mut(&s.group_index).unwrap();
			e.member_shares.push(s);
		}
	}

	if group_index_map.len() < check_share.group_threshold as usize {
		return Err(ErrorKind::Mneumonic(format!(
			"Insufficient number of mnemonic groups ({}). The required number \
			 of groups is {}.",
			group_index_map.len(),
			check_share.group_threshold,
		)))?;
	}

	let groups: Vec<GroupShare> = group_index_map
		.into_iter()
		.map(|g| g.1)
		// remove groups where number of shares is below the member threshold
		.filter(|g| g.member_shares.len() >= check_share.group_threshold as usize)
		.collect();

	if groups.len() < check_share.group_threshold as usize {
		return Err(ErrorKind::Mneumonic(format!(
			"Insufficient number of groups with member counts that meet member threshold."
		)))?;
	}

	// TODO: Should probably return info making problem mnemonics easier to identify
	for g in groups.iter() {
		if g.member_shares.len() < g.member_threshold as usize {
			return Err(ErrorKind::Mneumonic(format!(
				"Insufficient number of mnemonics (Group {}). At least {} mnemonics \
				 are required.",
				g.group_index, g.member_threshold,
			)))?;
		}
		let test_share = g.member_shares[0].clone();
		for ms in g.member_shares.iter() {
			if test_share.member_threshold != ms.member_threshold {
				return Err(ErrorKind::Mneumonic(format!(
					"Mismatching member thresholds"
				)))?;
			}
		}
	}

	Ok(groups)
}

#[cfg(test)]
mod tests {
	use super::*;

	fn flatten_mnemonics(nms: &Vec<GroupShare>) -> Result<Vec<Vec<String>>, Error> {
		let mut ret = vec![];
		for m in nms {
			for s in m.member_shares.iter() {
				ret.push(s.to_mnemonic()?);
			}
		}
		Ok(ret)
	}

	#[test]
	fn generate_mnemonics_test() -> Result<(), Error> {
		let master_secret = b"\x0c\x94\x90\xbcn\xd6\xbc\xbf\xac>\xbe}\xeeV\xf2P".to_vec();

		// single 3 of 5 test, splat out all mnemonics
		println!("Single 3 of 5 Encoded: {:?}", master_secret);
		let mns = generate_mneumonics(1, &vec![(3, 5)], &master_secret, "", 0)?;
		for s in &mns {
			println!("{}", s);
		}
		let result = combine_mneumonics(&flatten_mnemonics(&mns)?, "")?;
		println!("Single 3 of 5 Decoded: {:?}", result);
		assert_eq!(result, master_secret);

		// Test a few distinct groups
		let mns = generate_mneumonics(
			2,
			&vec![(3, 5), (2, 5), (3, 3), (13, 16)],
			&master_secret,
			"",
			0,
		)?;
		for s in &mns {
			println!("{}", s);
		}
		let result = combine_mneumonics(&flatten_mnemonics(&mns)?, "")?;
		println!("Single 3 of 5 Decoded: {:?}", result);
		assert_eq!(result, master_secret);

		Ok(())
	}
}
