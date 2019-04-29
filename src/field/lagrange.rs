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
// Modifications Copyright 2019 ???
//
// TODO: LICENSE TEXT
//

use crate::field::gf256::Gf256;
use crate::field::poly::Poly;

/// Evaluates an interpolated polynomial at `Gf256::zero()` where
/// the polynomial is determined using barycentric Lagrange
/// interpolation based on the given `points` in
/// the G(2^8) Galois field.
pub fn _interpolate_at(k: u8, points: &[(u8, u8)]) -> u8 {
	_barycentric_interpolate_at(k as usize, points)
}

/// Barycentric Lagrange interpolation algorithm from "Polynomial
/// Interpolation: Langrange vs Newton" by Wilhelm Werner. Evaluates
/// the polynomial at `Gf256::zero()`.
#[inline]
fn _barycentric_interpolate_at(k: usize, points: &[(u8, u8)]) -> u8 {
	// Compute the barycentric weights `w`.
	let mut w = vec![Gf256::zero(); k];
	w[0] = Gf256::one();

	let mut x = Vec::with_capacity(k);
	x.push(Gf256::from_byte(points[0].0));

	for i in 1..k {
		x.push(Gf256::from_byte(points[i].0));
		for j in 0..i {
			let delta = x[j] - x[i];
			assert_ne!(delta.poly, 0, "Duplicate shares");
			w[j] /= delta;
			w[i] -= w[j];
		}
	}

	// Evaluate the second or "true" form of the barycentric
	// interpolation formula at `Gf256::zero()`.
	let (mut num, mut denom) = (Gf256::zero(), Gf256::zero());
	for i in 0..k {
		assert_ne!(x[i].poly, 0, "Invalid share x = 0");
		let diff = w[i] / x[i];
		num += diff * Gf256::from_byte(points[i].1);
		denom += diff;
	}

	(num / denom).to_byte()
}

/// Computeds the coefficient of the Lagrange polynomial interpolated
/// from the given `points`, in the G(2^8) Galois field.
pub fn interpolate(points: &[(Gf256, Gf256)]) -> Poly {
	let len = points.len();

	let mut poly = vec![Gf256::zero(); len];

	for &(x, y) in points {
		let mut coeffs = vec![Gf256::zero(); len];
		coeffs[0] = y;

		let mut prod = Gf256::one();
		for &(x1, _) in points {
			if x != x1 {
				prod *= x - x1;

				let mut prec = Gf256::zero();
				coeffs = coeffs
					.into_iter()
					.map(|coeff| {
						let new_coeff = coeff * (-x1) + prec;
						prec = coeff;
						new_coeff
					})
					.collect();
			}
		}

		poly = poly
			.iter()
			.zip(coeffs.iter())
			.map(|(&old_coeff, &add)| old_coeff + add / prod)
			.collect();
	}

	Poly::new(poly)
}

#[cfg(test)]
#[allow(trivial_casts)]
mod tests {

	use super::*;
	use crate::field::gf256::*;
	use quickcheck::*;
	use std;

	quickcheck! {

		fn interpolate_evaluate_at_works(ys: Vec<Gf256>) -> TestResult {
			if ys.is_empty() || ys.len() > std::u8::MAX as usize {
				return TestResult::discard();
			}

			let points = ys.into_iter()
						   .zip(1..std::u8::MAX)
						   .map(|(y, x)| (gf256!(x), y))
						   .collect::<Vec<_>>();
			let poly = interpolate(&points);

			for (x, y) in points {
				if poly.evaluate_at(x) != y {
					return TestResult::failed();
				}
			}

			TestResult::passed()
		}

		fn interpolate_evaluate_at_0_eq_evaluate_at(ys: Vec<u8>) -> TestResult {
			if ys.is_empty() || ys.len() > std::u8::MAX as usize {
				return TestResult::discard();
			}

			let points = ys.into_iter()
						   .zip(1..std::u8::MAX)
						   .map(|(y, x)| (x, y))
						   .collect::<Vec<_>>();

			let elems = points
				.iter()
				.map(|&(x, y)| (gf256!(x), gf256!(y)))
				.collect::<Vec<_>>();

			let poly = interpolate(&elems);

			let equals = poly.evaluate_at(Gf256::zero()).to_byte()
				== _interpolate_at(points.len() as u8, points.as_slice());

			TestResult::from_bool(equals)
		}

	}

}
