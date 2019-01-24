
/// This code is inspired by
/// [RustCrypto's `BigUint` implementation](https://github.com/rust-num/num-bigint/blob/eb003cc41b604658c885c052583ea9f453f9c910/src/biguint.rs).

/// This library will fail to compile because of two constant-timedness violations :
/// the count of leading zeroes and a direct comparison to 0.

use secret_integers::*;

type BigDigit = U32;
pub const BITS: usize = 32;

/// A big unsigned integer type.
pub struct BigUint {
    data: Vec<BigDigit>,
}

impl BigUint {
    fn is_zero(&self) -> bool {
        self.data.is_empty()
    }

    fn bits(&self) -> usize {
       if self.is_zero() {
           return 0;
       }
       let zeros = self.data.last().unwrap().leading_zeros();
       return self.data.len() * BITS - zeros as usize;
   }

}

// Extract bitwise digits that evenly divide BigDigit
fn to_bitwise_digits_le(u: &BigUint, bits: usize) -> Vec<U8> {
    debug_assert!(!u.is_zero() && bits <= 8 && BITS % bits == 0);

    let last_i = u.data.len() - 1;
    let mask: BigDigit = ((1 << bits) - 1).into();
    let digits_per_big_digit = BITS / bits;
    let digits = (u.bits() + bits - 1) / bits;
    let mut res = Vec::with_capacity(digits);

    for mut r in u.data[..last_i].iter().cloned() {
        for _ in 0..digits_per_big_digit {
            res.push((r & mask).into());
            r >>= (bits as u32).into();
        }
    }

    let mut r = u.data[last_i];
    while r != 0 {
        res.push((r & mask).into());
        r >>= (bits as u32).into();
    }

    res
}
