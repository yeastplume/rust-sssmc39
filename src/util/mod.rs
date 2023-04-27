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

//! cryptography and utility functions

pub mod bitpacker;
pub mod encrypt;
pub mod hex;
pub mod rs1024;

use rand::{thread_rng, Rng};

// fill a u8 vec with n bytes of random data
pub fn fill_vec_rand(n: usize) -> Vec<u8> {
	let mut v = vec![];
	for _ in 0..n {
		v.push(thread_rng().gen());
	}
	v
}
