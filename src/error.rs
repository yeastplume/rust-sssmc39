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

//! Error types for ssmc39 crate

use failure::{Backtrace, Context, Fail};
use std::env;
use std::fmt::{self, Display};

/// Error definition
#[derive(Debug, Fail)]
pub struct Error {
	inner: Context<ErrorKind>,
}

/// Wallet errors, mostly wrappers around underlying crypto or I/O errors.
#[derive(Clone, Eq, PartialEq, Debug, Fail)]
pub enum ErrorKind {
	/// Configuration error, with details
	#[fail(display = "Configuration Error: {}", _0)]
	Config(String),

	/// Inconsistency between different arguments
	#[fail(display = "Argument Error: {}", _0)]
	Argument(String),

	/// Problems with a mnemonic or inconsistent mnemonics
	#[fail(display = "Mnemonic Error: {}", _0)]
	Mnemonic(String),

	/// Assembling the full master secret resulted in an incorrect checksum
	#[fail(display = "Digest Error: {}", _0)]
	Digest(String),

	/// Invalid usage of BitPacker.add_uX (num_bits longer than the size of uX)
	#[fail(display = "BitVec Error: {}", _0)]
	BitVec(String),

	/// (unused currently)
	#[fail(display = "Checksum Validation Error: {}", _0)]
	Checksum(String),

	/// Invalid value of one of the arguments
	#[fail(display = "Value Error: {}", _0)]
	Value(String),

	/// Invalid usage of BitPacker.remove_padding (num_bits contained set bits)
	#[fail(display = "Padding Error: All padding bits must be 0")]
	Padding,

	/// (unused currently)
	#[fail(display = "Generic error: {}", _0)]
	GenericError(String),
}

impl Display for Error {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		let show_bt = match env::var("RUST_BACKTRACE") {
			Ok(r) => r == "1",
			Err(_) => false,
		};
		let backtrace = match self.backtrace() {
			Some(b) => format!("{}", b),
			None => String::from("Unknown"),
		};
		let inner_output = format!("{}", self.inner,);
		let backtrace_output = format!("\n Backtrace: {}", backtrace);
		let mut output = inner_output;
		if show_bt {
			output.push_str(&backtrace_output);
		}
		Display::fmt(&output, f)
	}
}

impl Error {
	/// get kind
	pub fn kind(&self) -> ErrorKind {
		self.inner.get_context().clone()
	}
	/// get cause string
	pub fn cause_string(&self) -> String {
		match self.cause() {
			Some(k) => format!("{}", k),
			None => "Unknown".to_string(),
		}
	}
	/// get cause
	pub fn cause(&self) -> Option<&dyn Fail> {
		self.inner.cause()
	}
	/// get backtrace
	pub fn backtrace(&self) -> Option<&Backtrace> {
		self.inner.backtrace()
	}
}

impl From<ErrorKind> for Error {
	fn from(kind: ErrorKind) -> Error {
		Error {
			inner: Context::new(kind),
		}
	}
}

impl From<Context<ErrorKind>> for Error {
	fn from(inner: Context<ErrorKind>) -> Error {
		Error { inner }
	}
}
