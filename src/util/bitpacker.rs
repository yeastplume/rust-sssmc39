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

//! Operations that allow packing bits from primitives into a bitvec
//! Slower, but easier to follow and modify than a lot of bit twiddling
//! BigEndian, as is bitvec default

use bitvec::prelude::*;

use crate::error::{Error, ErrorKind};

/// Simple struct that wraps a bitvec and defines packing operations on it
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BitPacker {
	bv: BitVec,
}

//TODO:
// * Works, but:
// * Faster
// * Generics
// * Iterator for reading values
//

impl BitPacker {
	/// Create a new bitpacker
	pub fn new() -> Self {
		BitPacker { bv: BitVec::new() }
	}

	/// Remove bits from end to meet boundary (for reading in u8 arrays)
	pub fn normalize(&mut self, radix: usize) {
		while self.bv.len() % radix != 0 {
			self.bv.pop();
		}
	}

	/// Append num_bits of zero padding to the internal bitvec
	pub fn append_padding(&mut self, num_bits: u8) {
		for _ in 0..num_bits {
			self.bv.push(false);
		}
	}

	/// Append each element of a u8 vec to the bitvec
	pub fn append_vec_u8(&mut self, data: &[u8]) -> Result<(), Error> {
		for b in data {
			self.append_u8(*b, 8)?;
		}
		Ok(())
	}

	/// Return n u8s from bitvec
	pub fn get_vec_u8(&mut self, start_pos: usize, len: usize) -> Result<Vec<u8>, Error> {
		let mut retvec = vec![];
		for i in (start_pos..len * 8).step_by(8) {
			retvec.push(self.get_u8(i, 8)?);
		}
		Ok(retvec)
	}

	/// Append first num_bits of a u32 to the bitvec. num_bits must be <= 32
	pub fn append_u32(&mut self, val: u32, num_bits: u8) -> Result<(), Error> {
		if num_bits > 32 {
			return Err(ErrorKind::BitVec(
				"number of bits to pack must be <= 32".to_string(),
			))?;
		}
		for i in (0u8..num_bits).rev() {
			if val & 2u32.pow(u32::from(i)) == 0 {
				self.bv.push(false);
			} else {
				self.bv.push(true);
			}
		}
		Ok(())
	}

	/// Append first num_bits of a u16 to the bitvec. num_bits must be <= 16
	pub fn append_u16(&mut self, val: u16, num_bits: u8) -> Result<(), Error> {
		if num_bits > 16 {
			return Err(ErrorKind::BitVec(
				"number of bits to pack must be <= 16".to_string(),
			))?;
		}
		for i in (0u8..num_bits).rev() {
			if val & 2u16.pow(u32::from(i)) == 0 {
				self.bv.push(false);
			} else {
				self.bv.push(true);
			}
		}
		Ok(())
	}

	/// Append first num_bits of a u8 to the bitvec, num_bits must be <= 8
	pub fn append_u8(&mut self, val: u8, num_bits: u8) -> Result<(), Error> {
		if num_bits > 8 {
			return Err(ErrorKind::BitVec(
				"number of bits to pack must be <= 8".to_string(),
			))?;
		}
		for i in (0u8..num_bits).rev() {
			if val & 2u8.pow(u32::from(i)) == 0 {
				self.bv.push(false);
			} else {
				self.bv.push(true);
			}
		}
		Ok(())
	}

	/// Retrieve num_bits from the given index as a u8
	pub fn get_u8(&self, index: usize, num_bits: usize) -> Result<u8, Error> {
		let mut retval: u8 = 0;
		for i in index..index + num_bits {
			if i < self.bv.len() && self.bv[i] {
				retval += 1;
			}
			if i < index + num_bits - 1 {
				retval <<= 1;
			}
		}
		Ok(retval)
	}

	/// Retrieve num_bits from the given index as a u16
	pub fn get_u16(&self, index: usize, num_bits: usize) -> Result<u16, Error> {
		let mut retval: u16 = 0;
		for i in index..index + num_bits {
			if i < self.bv.len() && self.bv[i] {
				retval += 1;
			}
			if i < index + num_bits - 1 {
				retval <<= 1;
			}
		}
		Ok(retval)
	}

	/// Retrieve num_bits from the given index as a u32
	pub fn get_u32(&self, index: usize, num_bits: usize) -> Result<u32, Error> {
		let mut retval: u32 = 0;
		for i in index..index + num_bits {
			if i < self.bv.len() && self.bv[i] {
				retval += 1;
			}
			if i < index + num_bits - 1 {
				retval <<= 1;
			}
		}
		Ok(retval)
	}

	/// Return length of internal bit vector
	pub fn len(&self) -> usize {
		self.bv.len()
	}

	/// Return bitvec between m and n
	pub fn split_out(&mut self, m: usize, n: usize) {
		self.bv.split_off(n);
		self.bv = self.bv.split_off(m);
	}

	/// Return bitvec between m and n
	pub fn remove_padding(&mut self, num_bits: usize) -> Result<(), Error> {
		let mut removed = self.bv.clone();
		self.bv = removed.split_off(num_bits);
		if removed.count_ones() > 0 {
			return Err(ErrorKind::Padding)?;
		}
		Ok(())
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	use crate::error::Error;

	#[test]
	fn bit_packer() -> Result<(), Error> {
		let mut bp = BitPacker::new();
		let val1: u16 = 32534;
		let val2: u8 = 12;
		let val3: u8 = 15;
		let val4: u8 = 8;
		let val5: u16 = 934;
		bp.append_u16(val1, 15)?;
		bp.append_u8(val2, 5)?;
		bp.append_u8(val3, 4)?;
		bp.append_u8(val4, 4)?;
		bp.append_u16(val5, 10)?;
		assert_eq!(bp.len(), 38);
		assert_eq!(val1, bp.get_u16(0, 15)?);
		assert_eq!(val2, bp.get_u8(15, 5)?);
		assert_eq!(val3, bp.get_u8(20, 4)?);
		assert_eq!(val4, bp.get_u8(24, 4)?);
		assert_eq!(val5, bp.get_u16(28, 10)?);
		assert_eq!(u32::from(val5), bp.get_u32(28, 10)?);
		Ok(())
	}
}
