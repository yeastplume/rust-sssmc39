// Copyright 2019 ???
//
// TODO: LICENSE TEXT
//
//

//! Operations that allow packing bits from primitives into a bitvec
//! Slower, but easier to follow and modify than a lot of bit twiddling
//! BigEndian, as is bitvec default

use bitvec::BitVec;

use crate::error::{Error, ErrorKind};

/// Simple struct that wraps a bitvec and defines packing operations on it
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BitPacker {
	bv: BitVec,
}

impl BitPacker {
	/// Create a new bitpacker
	pub fn new() -> Self {
		BitPacker { bv: BitVec::new() }
	}

	/// Append num_bits of zero padding to the internal bitvec
	pub fn append_padding(&mut self, num_bits: u8) {
		for _ in 0..num_bits {
			self.bv.push(false);
		}
	}

	/// Append each element of a u8 vec to the bitvec
	pub fn append_vec_u8(&mut self, data: &Vec<u8>) -> Result<(), Error> {
		for i in 0..data.len() {
			self.append_u8(data[i], 8)?;
		}
		Ok(())
	}

	/// Append first num_bits of a u16 to the bitvec. num_bits must be <= 16
	pub fn append_u16(&mut self, val: u16, num_bits: u8) -> Result<(), Error> {
		if num_bits > 16 {
			return Err(ErrorKind::BitVec(format!(
				"number of bits to pack must be <= 16",
			)))?;
		}
		for i in (0u8..num_bits).rev() {
			if val & 2u16.pow(i as u32) == 0 {
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
			return Err(ErrorKind::BitVec(format!(
				"number of bits to pack must be <= 8",
			)))?;
		}
		for i in (0u8..num_bits).rev() {
			if val & 2u8.pow(i as u32) == 0 {
				self.bv.push(false);
			} else {
				self.bv.push(true);
			}
		}
		Ok(())
	}

	/// Return length of internal bit vector
	pub fn len(&self) -> usize {
		self.bv.len()
	}
}
