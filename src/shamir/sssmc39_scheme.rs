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

use std::collections::BTreeMap;
use std::fmt;

use crate::util;

/// Struct for returned shares
#[derive(Debug, Clone, Default, PartialEq, Eq)]
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

impl GroupShare {
	/// return list of mnemonics
	pub fn mnemonic_list(&self) -> Result<Vec<Vec<String>>, Error> {
		let mut ret_vec = vec![];
		for s in &self.member_shares {
			ret_vec.push(s.to_mnemonic()?);
		}
		Ok(ret_vec)
	}

	/// return list of mnemonics as space separated strings
	pub fn mnemonic_list_flat(&self) -> Result<Vec<String>, Error> {
		let mut ret_vec = vec![];
		for s in &self.member_shares {
			ret_vec.push(s.to_mnemonic()?.iter().fold(String::new(), |mut acc, s| {
				acc.push_str(s);
				acc.push(' ');
				acc
			}))
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
pub fn generate_mnemonics(
	group_threshold: u8,
	groups: &[(u8, u8)],
	master_secret: &[u8],
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
			(f64::from(proto_share.config.min_strength_bits) / 8f64).ceil(),
		)))?;
	}

	if master_secret.len() % 2 != 0 {
		return Err(ErrorKind::Value(
			"The length of the master secret in bytes must be an even number".to_string(),
		))?;
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
			iteration_exponent,
			group_index: i as u8,
			group_threshold,
			group_count: gs_len as u8,
			member_threshold,
			member_shares,
		});
	}

	Ok(retval)
}

pub fn generate_mnemonics_random(
	group_threshold: u8,
	groups: &[(u8, u8)],
	strength_bits: u16,
	passphrase: &str,
	iteration_exponent: u8,
) -> Result<Vec<GroupShare>, Error> {
	let proto_share = Share::new()?;
	if strength_bits < proto_share.config.min_strength_bits {
		return Err(ErrorKind::Value(format!(
			"The requested strength of the master secret({} bits) must be at least {} bits.",
			strength_bits, proto_share.config.min_strength_bits,
		)))?;
	}
	if strength_bits % 16 != 0 {
		return Err(ErrorKind::Value(format!(
			"The requested strength of the master secret({} bits) must be a multiple of 16 bits.",
			strength_bits,
		)))?;
	}
	generate_mnemonics(
		group_threshold,
		groups,
		&util::fill_vec_rand(strength_bits as usize / 8),
		passphrase,
		iteration_exponent,
	)
}

/// Combines mnemonic shares to obtain the master secret which was previously split using
/// Shamir's secret sharing scheme.
/// mnemonics: List of mnemonics.
/// passphrase: The passphrase used to encrypt the master secret.
/// return: The master secret.
pub fn combine_mnemonics(mnemonics: &[Vec<String>], passphrase: &str) -> Result<Vec<u8>, Error> {
	let group_shares = decode_mnemonics(mnemonics)?;
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
		.collect::<Vec<_>>();
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

/// Decodes all Mnemonics to a list of shares and performs error checking
fn decode_mnemonics(mnemonics: &[Vec<String>]) -> Result<Vec<GroupShare>, Error> {
	let mut shares = vec![];
	if mnemonics.is_empty() {
		return Err(ErrorKind::Mnemonic(
			"List of mnemonics is empty.".to_string(),
		))?;
	}
	let check_len = mnemonics[0].len();
	for m in mnemonics {
		if m.len() != check_len {
			return Err(ErrorKind::Mnemonic(
				"Invalid set of mnemonics. All mnemonics must have the same length.".to_string(),
			))?;
		}
		shares.push(Share::from_mnemonic(m)?);
	}

	let check_share = shares[0].clone();
	for s in shares.iter() {
		if s.identifier != check_share.identifier
			|| s.iteration_exponent != check_share.iteration_exponent
		{
			return Err(ErrorKind::Mnemonic(format!(
				"Invalid set of mnemonics. All mnemonics must begin with the same {} words. \
				 (Identifier and iteration exponent must be the same).",
				s.config.id_exp_length_words,
			)))?;
		}
		if s.group_threshold != check_share.group_threshold {
			return Err(ErrorKind::Mnemonic(
				"Invalid set of mnemonics. All mnemonics must have the same group threshold"
					.to_string(),
			))?;
		}
		if s.group_count != check_share.group_count {
			return Err(ErrorKind::Mnemonic(
				"Invalid set of mnemonics. All mnemonics must have the same group count"
					.to_string(),
			))?;
		}
	}

	let mut group_index_map = BTreeMap::new();

	for s in shares {
		if !group_index_map.contains_key(&s.group_index) {
			let group_share = GroupShare {
				group_id: s.identifier,
				group_index: s.group_index,
				group_threshold: s.group_threshold,
				iteration_exponent: s.iteration_exponent,
				group_count: s.group_count,
				member_shares: vec![s.clone()],
				member_threshold: s.member_threshold,
			};
			group_index_map.insert(group_share.group_index, group_share);
		} else {
			let e = group_index_map.get_mut(&s.group_index).unwrap();
			e.member_shares.push(s);
		}
	}

	if group_index_map.len() < check_share.group_threshold as usize {
		return Err(ErrorKind::Mnemonic(format!(
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
		.filter(|g| g.member_shares.len() >= g.member_threshold as usize)
		.collect();

	if groups.len() < check_share.group_threshold as usize {
		return Err(ErrorKind::Mnemonic(
			"Insufficient number of groups with member counts that meet member threshold."
				.to_string(),
		))?;
	}

	// TODO: Should probably return info making problem mnemonics easier to identify
	for g in groups.iter() {
		if g.member_shares.len() < g.member_threshold as usize {
			return Err(ErrorKind::Mnemonic(format!(
				"Insufficient number of mnemonics (Group {}). At least {} mnemonics \
				 are required.",
				g.group_index, g.member_threshold,
			)))?;
		}
		let test_share = g.member_shares[0].clone();
		for ms in g.member_shares.iter() {
			if test_share.member_threshold != ms.member_threshold {
				return Err(ErrorKind::Mnemonic(
					"Mismatching member thresholds".to_string(),
				))?;
			}
		}
	}

	Ok(groups)
}

#[cfg(test)]
mod tests {
	use super::*;

	fn flatten_mnemonics(nms: &[GroupShare]) -> Result<Vec<Vec<String>>, Error> {
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
		let mns = generate_mnemonics(1, &[(3, 5)], &master_secret, "", 0)?;
		for s in &mns {
			println!("{}", s);
		}
		let result = combine_mnemonics(&flatten_mnemonics(&mns)?, "")?;
		println!("Single 3 of 5 Decoded: {:?}", result);
		assert_eq!(result, master_secret);

		// Test a few distinct groups
		let mns = generate_mnemonics(
			2,
			&[(3, 5), (2, 5), (3, 3), (13, 16)],
			&master_secret,
			"",
			0,
		)?;
		for s in &mns {
			println!("{}", s);
		}
		let result = combine_mnemonics(&flatten_mnemonics(&mns)?, "")?;
		println!("Single 3 of 5 Decoded: {:?}", result);
		assert_eq!(result, master_secret);

		// work through some varying sized secrets
		let mut master_secret = b"\x0c\x94\x90\xbcn\xd6\xbc\xbf\xac>\xbe}\xeeV\xf2P".to_vec();
		for _ in 0..32 {
			master_secret.push(0);
			master_secret.push(1);

			println!("Single 3 of 5 Encoded: {:?}", master_secret);
			println!("master secret length: {}", master_secret.len());
			let mns = generate_mnemonics(1, &[(3, 5)], &master_secret, "", 0)?;
			for s in &mns {
				println!("{}", s);
			}
			let result = combine_mnemonics(&flatten_mnemonics(&mns)?, "")?;
			println!("Single 3 of 5 Decoded: {:?}", result);
			assert_eq!(result, master_secret);
		}

		// Test case for particular case which failed with different threshold lenghts
		// TODO: Fold this in to other tests
		let one = "slavery flea acrobat eclipse cultural emission yield invasion seafood says insect square bucket orbit leaves closet heat ugly database decorate";
		let two = "slavery flea acrobat emerald aviation escape year axle method forget rebound burden museum game suitable brave texture deploy together flash";
		let three = "slavery flea acrobat envelope best ceiling dragon threaten isolate headset decrease organize crunch fiction sniff carbon museum username glasses plunge";
		let four = "slavery flea beard echo cradle rebound penalty minister literary object have hazard elephant meaning enemy empty result capture peanut believe";
		let five = "slavery flea beard email blind lips evaluate repair decent rich mortgage swimming branch decision unkind ultimate military sugar prepare airport";
		let mut input = vec![];
		input.push(one.split(' ').map(|s| s.to_owned()).collect());
		input.push(two.split(' ').map(|s| s.to_owned()).collect());
		input.push(three.split(' ').map(|s| s.to_owned()).collect());
		input.push(four.split(' ').map(|s| s.to_owned()).collect());
		input.push(five.split(' ').map(|s| s.to_owned()).collect());
		let _result = combine_mnemonics(&input, "TREZOR")?;

		Ok(())
	}

	// For temporary use as we have no command-line at present
	#[test]
	fn split_master_secret() -> Result<(), Error> {
		let master_secret = b"fdd99010e03f3141662adb33644d5fd2bea0238fa805a2d21e396a22b926558c";
		let mns = generate_mnemonics(1, &[(3, 5)], &master_secret.to_vec(), "", 0)?;
		for s in &mns {
			println!("{}", s);
		}
		let one = "ending senior academic acne acne lizard armed wrist fancy center blimp broken branch ceiling type bishop senior window mother dominant humidity kidney flip leader cover pupal swimming quarter findings picture much impulse answer threaten bishop express brother sharp unwrap bulge leaves guest ladybug imply thumb dress brave orbit orbit garbage vexed brave deploy tofu regular unusual hunting carbon year";
		let two = "ending senior academic agree acid grill magazine trip impact diagnose headset year puny adorn swimming knife aquatic airline prayer hairy unfold forbid diminish sweater brave column holy spit superior replace script oasis firefly scared goat divorce oral laundry violence merit golden founder unusual taste preach ruin lying bumpy single glasses fitness argue daisy secret loud squeeze theater husky already";
		let three = "ending senior academic amazing academic carbon sheriff march ordinary advocate climate quarter explain view glasses distance scandal modify maiden welcome include webcam snapshot lilac finance faint facility quantity daughter trash formal failure execute grasp necklace trust bishop privacy library infant slim envy parcel boring mixture deploy dough deny patrol evening brave idea blessing slush lizard woman teaspoon news exclude";
		let four = "ending senior academic arcade acquire work exceed network revenue blanket force fiber ting standard fatigue extend acid holiday raspy pink vegan survive river step golden scandal tendency spray parcel vintage amuse remove best else unknown overall mild breathe nuclear wrist criminal jury deal rescue symbolic slow predator railroad verify involve require graduate ambition unknown repair scandal hobo voice railroad";
		let five = "ending senior academic axle acquire golden velvet depart swing endorse champion estate slush alien burning painting obesity surprise punish gasoline elephant educate declare rebuild plains making unkind carve exotic unfold counter cowboy extra fantasy cleanup pickup increase type deliver together fumes nylon acrobat fatigue listen elder toxic losing paper image aide satisfy award axis evoke capital academic violence canyon";
		let mut input = vec![];
		input.push(one.split(' ').map(|s| s.to_owned()).collect());
		input.push(two.split(' ').map(|s| s.to_owned()).collect());
		input.push(three.split(' ').map(|s| s.to_owned()).collect());
		input.push(four.split(' ').map(|s| s.to_owned()).collect());
		input.push(five.split(' ').map(|s| s.to_owned()).collect());
		let result = combine_mnemonics(&input, "")?;
		println!("Result: {}", String::from_utf8(result).unwrap());
		Ok(())
	}
}
