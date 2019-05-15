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

//! Main API definition
//! Should ultimately allow some flexibility around how shares can be
//! provided and returned (e.g. provide hex string instead of mnemonics)

#![deny(non_upper_case_globals)]
#![deny(non_camel_case_types)]
#![deny(non_snake_case)]
#![deny(unused_mut)]
#![warn(missing_docs)]

#[macro_use]
extern crate lazy_static;

mod error;
mod field;
mod shamir;
mod util;

pub use error::{Error, ErrorKind};
pub use shamir::{GroupShare, Share};
// TODO: only exposed for tests
pub use util::hex::{to_hex, from_hex};

//TODO: Proper docs
pub fn generate_mnemonics(
	group_threshold: u8,
	groups: &Vec<(u8, u8)>,
	master_secret: &Vec<u8>,
	passphrase: &str,
	iteration_exponent: u8,
) -> Result<Vec<GroupShare>, Error> {
	shamir::generate_mnemonics(
		group_threshold,
		groups,
		master_secret,
		passphrase,
		iteration_exponent,
	)
}

// TODO: Proper docs
// should allow for different input formats
pub fn combine_mnemonics(
	mnemonics: &Vec<Vec<String>>,
	passphrase: &str,
) -> Result<Vec<u8>, Error> {
	shamir::combine_mnemonics(mnemonics, passphrase)
}

// TODO: Proper docs
// Generate a random master secret and return shares
pub fn generate_mnemonics_random(
	group_threshold: u8,
	groups: &Vec<(u8, u8)>,
	strength_bits: u16,
	passphrase: &str,
	iteration_exponent: u8,
) -> Result<Vec<GroupShare>, Error> {
	shamir::generate_mnemonics_random(
		group_threshold,
		groups,
		strength_bits,
		passphrase,
		iteration_exponent,
	)
}

