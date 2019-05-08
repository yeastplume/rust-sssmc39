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

mod config;
mod error;
mod field;
mod shamir;
mod util;

#[macro_use]
extern crate lazy_static;

use error::{Error, ErrorKind};

use config::ShamirMnemonicConfig;
use shamir::{Share, Splitter};

use std::fmt;

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

/// Main Struct
pub struct ShamirMnemonic {
	/// Configuration values
	config: ShamirMnemonicConfig,
}

impl ShamirMnemonic {
	/// Create new
	pub fn new(config: Option<&ShamirMnemonicConfig>) -> ShamirMnemonic {
		ShamirMnemonic {
			config: match config {
				Some(c) => c.to_owned(),
				None => ShamirMnemonicConfig::new(),
			},
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
	pub fn generate_mnemonics(
		&self,
		group_threshold: u8,
		groups: &Vec<(u8, u8)>,
		master_secret: &Vec<u8>,
		passphrase: &str,
		iteration_exponent: u8,
	) -> Result<Vec<GroupShare>, Error> {

		if master_secret.len() * 8 < self.config.min_strength_bits as usize {
			return Err(ErrorKind::Value(format!(
				"The length of the master secret ({} bytes) must be at least {} bytes.",
				master_secret.len(),
				(self.config.min_strength_bits as f64 / 8f64).ceil(),
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

		let encoder = util::encrypt::MasterSecretEnc::new(
			self.config.round_count,
			self.config.min_iteration_count,
			&self.config.customization_string,
		)?;

		// Generate a 'proto share' so to speak, with identifer generated and group data filled
		let mut proto_share = Share::new()?;
		proto_share.group_threshold = group_threshold;
		proto_share.group_count = groups.len() as u8;

		let encrypted_master_secret =
			encoder.encrypt(master_secret, passphrase, iteration_exponent, proto_share.identifier);

		let sp = Splitter::new(None);

		let group_shares = sp.split_secret(
			&proto_share,
			group_threshold,
			groups.len() as u8,
			&encrypted_master_secret,
		)?;

		let mut retval: Vec<GroupShare> = vec![];

		let gs_len = group_shares.len();
		for (i, mut elem) in group_shares.into_iter().enumerate() {
			elem.group_index = i as u8;
			elem.group_threshold = group_threshold;
			elem.group_count = gs_len as u8;
			let (member_threshold, member_count) = groups[i];
			let member_shares = sp.split_secret(
				&elem,
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
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn generate_mnemonics() -> Result<(), error::Error> {
		let sm = ShamirMnemonic::new(None);
		let master_secret = b"\x0c\x94\x90\xbcn\xd6\xbc\xbf\xac>\xbe}\xeeV\xf2P".to_vec();
		let mns = sm.generate_mnemonics(2, &vec![(2, 2), (3, 5), (6, 10)], &master_secret, "", 0)?;

		for s in mns {
			println!("{}", s);
		}

		Ok(())
	}
}
