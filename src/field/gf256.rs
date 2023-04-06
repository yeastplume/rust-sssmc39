// Derived from RustySecrets Project at
// https://github.com/SpinResearch/RustySecrets.git
//
// BSD 3-Clause License
//
// Copyright (c) 2016-2018, Spin Research
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// * Redistributions of source code must retain the above copyright notice, this
//   list of conditions and the following disclaimer.
//
// * Redistributions in binary form must reproduce the above copyright notice,
//   this list of conditions and the following disclaimer in the documentation
//   and/or other materials provided with the distribution.
//
// * Neither the name of the copyright holder nor the names of its
//   contributors may be used to endorse or promote products derived from
//   this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//

//
// Modifications Copyright 2019 The Grin Developers
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
//

//! This module provides the Gf256 type which is used to represent
//! elements of a finite field with 256 elements.

use std::fmt;
use std::ops::{Add, AddAssign, Div, DivAssign, Mul, MulAssign, Neg, Sub, SubAssign};

#[derive(Copy, Clone)]
pub struct Tables {
	pub exp: [u8; 255],
	pub log: [u8; 256],
}

// Just for testing against the reference
impl PartialEq for Tables {
	fn eq(&self, other: &Tables) -> bool {
		for i in 0..255 {
			if self.exp[i] != other.exp[i] {
				return false;
			}
			if self.log[i] != other.log[i] {
				return false;
			}
		}
		true
	}
}

impl fmt::Debug for Tables {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		let _ = writeln!(f, "exp: (");
		for i in 0..255 {
			let _ = write!(f, "{}, ", self.exp[i]);
		}
		let _ = writeln!(f, ")");
		let _ = writeln!(f, "log: (");
		for i in 0..256 {
			let _ = write!(f, "{}, ", self.log[i]);
		}
		writeln!(f, ")")
	}
}

impl Tables {
	/// Generates a table of discrete logarithms and exponents in Gf(256) using the polynomial
	/// x + 1 as the base
	pub fn generate() -> Tables {
		let mut tabs = Tables {
			exp: [0; 255],
			log: [0; 256],
		};

		let mut tmp: u16 = 1;
		for power in 0..255usize {
			tabs.exp[power] = tmp as u8;
			tabs.log[tmp as usize] = power as u8;
			// Multiply poly by the polynomial x + 1
			tmp = (tmp << 1) ^ tmp;
			// Reduce poly by x^8 + x^4 + x^3 +x + 1
			if (tmp & 0x100) > 0 {
				tmp ^= 0x11B;
			}
		}
		tabs
	}
}

lazy_static! {
	/// Static reference to Generated tables
	pub static ref TABLES: Tables = Tables::generate();
}

fn get_tables() -> &'static Tables {
	&TABLES
}

/// Type for elements of a finite field with 256 elements
#[derive(Copy, Debug, Clone, PartialEq, Eq)]
pub struct Gf256 {
	pub poly: u8,
}

impl Gf256 {
	/// returns the additive neutral element of the field
	#[inline]
	pub fn zero() -> Gf256 {
		Gf256 { poly: 0 }
	}
	/// returns the multiplicative neutral element of the field
	#[inline]
	pub fn one() -> Gf256 {
		Gf256 { poly: 1 }
	}
	#[inline]
	pub fn from_byte(b: u8) -> Gf256 {
		Gf256 { poly: b }
	}
	#[inline]
	pub fn to_byte(self) -> u8 {
		self.poly
	}
	pub fn exp(power: u8) -> Gf256 {
		let tabs = get_tables();
		Gf256::from_byte(tabs.exp[power as usize])
	}
	pub fn log(self) -> Option<u8> {
		if self.poly == 0 {
			None
		} else {
			let tabs = get_tables();
			Some(tabs.log[self.poly as usize])
		}
	}
	pub fn pow(mut self, mut exp: u8) -> Gf256 {
		let mut acc = Self::one();

		while exp > 1 {
			if (exp & 1) == 1 {
				acc *= self;
			}
			exp /= 2;
			self *= self;
		}

		if exp == 1 {
			acc *= self;
		}

		acc
	}
}

impl Add<Gf256> for Gf256 {
	type Output = Gf256;
	#[inline]
	#[allow(clippy::suspicious_arithmetic_impl)]
	fn add(self, rhs: Gf256) -> Gf256 {
		Gf256::from_byte(self.poly ^ rhs.poly)
	}
}

impl AddAssign<Gf256> for Gf256 {
	#[inline]
	fn add_assign(&mut self, rhs: Gf256) {
		*self = *self + rhs;
	}
}

impl Sub<Gf256> for Gf256 {
	type Output = Gf256;
	#[inline]
	#[allow(clippy::suspicious_arithmetic_impl)]
	fn sub(self, rhs: Gf256) -> Gf256 {
		Gf256::from_byte(self.poly ^ rhs.poly)
	}
}

impl SubAssign<Gf256> for Gf256 {
	#[inline]
	fn sub_assign(&mut self, rhs: Gf256) {
		*self = *self - rhs;
	}
}

impl Mul<Gf256> for Gf256 {
	type Output = Gf256;
	fn mul(self, rhs: Gf256) -> Gf256 {
		if let (Some(l1), Some(l2)) = (self.log(), rhs.log()) {
			let tmp = (u16::from(l1) + u16::from(l2)) % 255;
			Gf256::exp(tmp as u8)
		} else {
			Gf256 { poly: 0 }
		}
	}
}

impl MulAssign<Gf256> for Gf256 {
	fn mul_assign(&mut self, rhs: Gf256) {
		*self = *self * rhs;
	}
}

impl Div<Gf256> for Gf256 {
	type Output = Gf256;
	fn div(self, rhs: Gf256) -> Gf256 {
		let l2 = rhs.log().expect("division by zero");
		if let Some(l1) = self.log() {
			let tmp = (u16::from(l1) + 255 - u16::from(l2)) % 255;
			Gf256::exp(tmp as u8)
		} else {
			Gf256 { poly: 0 }
		}
	}
}

impl DivAssign<Gf256> for Gf256 {
	fn div_assign(&mut self, rhs: Gf256) {
		*self = *self / rhs;
	}
}

impl Neg for Gf256 {
	type Output = Gf256;
	fn neg(self) -> Gf256 {
		Gf256::zero() - self
	}
}

#[macro_export]
#[doc(hidden)]
macro_rules! gf256 {
	($e:expr) => {
		Gf256::from_byte($e)
	};
}

#[macro_export]
#[doc(hidden)]
macro_rules! gf256_vec {
    ( $( ($x:expr, $y:expr) ),* ) => {
        {
            let mut temp_vec = Vec::new();
            $(
                temp_vec.push((Gf256::from_byte($x), Gf256::from_byte($y)));
            )*
            temp_vec
        }
    };
    ( $( $x:expr ),* ) => {
        {
            let mut temp_vec = Vec::new();
            $(
                temp_vec.push(Gf256::from_byte($x));
            )*
            temp_vec
        }
    };
}

#[cfg(test)]
#[allow(trivial_casts)]
mod tests {

	use super::*;
	use quickcheck::*;

	mod vectors {
		use super::*;
		use flate2::read::GzDecoder;
		use itertools::Itertools;
		use std::fs::File;
		use std::io::{BufRead, BufReader};

		macro_rules! mk_test {
			($id:ident, $op:expr, $val:expr) => {
				mk_test!($id, $op, $val, 0);
			};
			($id:ident, $op:expr, $val:expr, $y:expr) => {
				#[test]
				fn $id() {
					let results = (0..256).cartesian_product($y..256).map(|(i, j)| {
						let (i, j) = (Gf256::from_byte(i as u8), Gf256::from_byte(j as u8));
						(i.to_byte(), j.to_byte(), $val(i, j).to_byte())
					});

					let ref_path = format!("tests/fixtures/gf256/gf256_{}.txt.gz", stringify!($id));
					let reference =
						BufReader::new(GzDecoder::new(File::open(ref_path).unwrap()).unwrap());

					for ((i, j, k), line) in results.zip(reference.lines()) {
						let left = format!("{} {} {} = {}", i, $op, j, k);
						let right = line.unwrap();
						assert_eq!(left, right);
					}
				}
			};
		}

		mk_test!(add, "+", |i: Gf256, j: Gf256| i + j);
		mk_test!(sub, "-", |i: Gf256, j: Gf256| i - j);
		mk_test!(mul, "*", |i: Gf256, j: Gf256| i * j);
		mk_test!(div, "/", |i: Gf256, j: Gf256| i.div(j), 1);
		mk_test!(pow, "^", |i: Gf256, j: Gf256| i.pow(j.to_byte()));
	}

	impl Arbitrary for Gf256 {
		fn arbitrary<G: Gen>(gen: &mut G) -> Gf256 {
			Gf256::from_byte(u8::arbitrary(gen))
		}
	}

	mod addition {
		use super::*;

		quickcheck! {
			fn law_associativity(a: Gf256, b: Gf256, c: Gf256) -> bool {
				(a + b) + c == a + (b + c)
			}

			fn law_commutativity(a: Gf256, b: Gf256) -> bool {
				let x = a + b;
				let y = b + a;
				x == y
			}

			fn law_distributivity(a: Gf256, b: Gf256, c: Gf256) -> bool {
				a * (b + c) == a * b + a * c
			}

			fn law_identity(a: Gf256) -> bool {
				a + Gf256::zero() == a && Gf256::zero() + a == a
			}

			fn law_inverses(a: Gf256) -> bool {
				a + (-a) == Gf256::zero() && (-a) + a == Gf256::zero()
			}
		}
	}

	mod multiplication {
		use super::*;

		quickcheck! {
			fn law_associativity(a: Gf256, b: Gf256, c: Gf256) -> bool {
				(a * b) * c == a * (b * c)
			}

			fn law_commutativity(a: Gf256, b: Gf256) -> bool {
				let x = a * b;
				let y = b * a;
				x == y
			}

			fn law_distributivity(a: Gf256, b: Gf256, c: Gf256) -> bool {
				(a + b) * c == a * c + b * c
			}

			fn law_identity(a: Gf256) -> bool {
				a * Gf256::one() == a && Gf256::one() * a == a
			}

			fn law_inverses(a: Gf256) -> TestResult {
				if a == Gf256::zero() {
					return TestResult::discard();
				}

				let left = a * (Gf256::one() / a) == Gf256::one();
				let right = (Gf256::one() / a) * a == Gf256::one();

				TestResult::from_bool(left && right)
			}
		}
	}
}

#[cfg(test)]
mod additional_tests {
	use super::*;

	// looks redundant for now, but just testing output against reference tables for development
	const REFERENCE_TABLE: Tables = Tables {
		exp: [
			1, 3, 5, 15, 17, 51, 85, 255, 26, 46, 114, 150, 161, 248, 19, 53, 95, 225, 56, 72, 216,
			115, 149, 164, 247, 2, 6, 10, 30, 34, 102, 170, 229, 52, 92, 228, 55, 89, 235, 38, 106,
			190, 217, 112, 144, 171, 230, 49, 83, 245, 4, 12, 20, 60, 68, 204, 79, 209, 104, 184,
			211, 110, 178, 205, 76, 212, 103, 169, 224, 59, 77, 215, 98, 166, 241, 8, 24, 40, 120,
			136, 131, 158, 185, 208, 107, 189, 220, 127, 129, 152, 179, 206, 73, 219, 118, 154,
			181, 196, 87, 249, 16, 48, 80, 240, 11, 29, 39, 105, 187, 214, 97, 163, 254, 25, 43,
			125, 135, 146, 173, 236, 47, 113, 147, 174, 233, 32, 96, 160, 251, 22, 58, 78, 210,
			109, 183, 194, 93, 231, 50, 86, 250, 21, 63, 65, 195, 94, 226, 61, 71, 201, 64, 192,
			91, 237, 44, 116, 156, 191, 218, 117, 159, 186, 213, 100, 172, 239, 42, 126, 130, 157,
			188, 223, 122, 142, 137, 128, 155, 182, 193, 88, 232, 35, 101, 175, 234, 37, 111, 177,
			200, 67, 197, 84, 252, 31, 33, 99, 165, 244, 7, 9, 27, 45, 119, 153, 176, 203, 70, 202,
			69, 207, 74, 222, 121, 139, 134, 145, 168, 227, 62, 66, 198, 81, 243, 14, 18, 54, 90,
			238, 41, 123, 141, 140, 143, 138, 133, 148, 167, 242, 13, 23, 57, 75, 221, 124, 132,
			151, 162, 253, 28, 36, 108, 180, 199, 82, 246,
		],
		log: [
			0, 0, 25, 1, 50, 2, 26, 198, 75, 199, 27, 104, 51, 238, 223, 3, 100, 4, 224, 14, 52,
			141, 129, 239, 76, 113, 8, 200, 248, 105, 28, 193, 125, 194, 29, 181, 249, 185, 39,
			106, 77, 228, 166, 114, 154, 201, 9, 120, 101, 47, 138, 5, 33, 15, 225, 36, 18, 240,
			130, 69, 53, 147, 218, 142, 150, 143, 219, 189, 54, 208, 206, 148, 19, 92, 210, 241,
			64, 70, 131, 56, 102, 221, 253, 48, 191, 6, 139, 98, 179, 37, 226, 152, 34, 136, 145,
			16, 126, 110, 72, 195, 163, 182, 30, 66, 58, 107, 40, 84, 250, 133, 61, 186, 43, 121,
			10, 21, 155, 159, 94, 202, 78, 212, 172, 229, 243, 115, 167, 87, 175, 88, 168, 80, 244,
			234, 214, 116, 79, 174, 233, 213, 231, 230, 173, 232, 44, 215, 117, 122, 235, 22, 11,
			245, 89, 203, 95, 176, 156, 169, 81, 160, 127, 12, 246, 111, 23, 196, 73, 236, 216, 67,
			31, 45, 164, 118, 123, 183, 204, 187, 62, 90, 251, 96, 177, 134, 59, 82, 161, 108, 170,
			85, 41, 157, 151, 178, 135, 144, 97, 190, 220, 252, 188, 149, 207, 205, 55, 63, 91,
			209, 83, 57, 132, 60, 65, 162, 109, 71, 20, 42, 158, 93, 86, 242, 211, 171, 68, 17,
			146, 217, 35, 32, 46, 137, 180, 124, 184, 38, 119, 153, 227, 165, 103, 74, 237, 222,
			197, 49, 254, 24, 13, 99, 140, 128, 192, 247, 112, 7,
		],
	};

	#[test]
	fn reference_table_gen() {
		println!("REFERENCE TABLES");
		println!("{:?}", REFERENCE_TABLE);
		println!("GENERATED TABLES");
		println!("{:?}", get_tables());
		assert!(get_tables() == &REFERENCE_TABLE);
	}
}
