//! This crate defines simple wrappers around Rust's integer type to guarantee they are used in
//! a constant-time fashion. Hence, division and direct comparison of these "secret" integers is
//! disallowed.
//!
//! These integers are intended to be the go-to type to use when implementing cryptographic
//! software, as they provide an extra automated check against use of variable-time operations.
//!
//! To use the crate, just import everything (`use secret_integers::*;`) and replace your integer
//! types with uppercase versions of their names (e.g. `u8` -> `U8`).
//!
//! # Examples
//!
//! In order to print information or test code involving your secret integers, you need first to
//! declassify them. Your crypto code should not contain any `declassify` occurence though to
//! guarantee constant-timedness. Make sure to specify the type of your literals when classifying
//! (e.g. `0x36u16`) or else you'll get a casting error.
//!
//! ```
//! # use secret_integers::*;
//! let x = U32::classify(1u32);
//! let y = U32::classify(2u32);
//! assert_eq!(U32::declassify(x + y), 3);
//! ```
//!
//! Using an illegal operation will get you a compile-time error:
//!
//! ```compile_fail
//! # use secret_integers::*;
//! let x = U32::classify(4u32);
//! let y = U32::classify(2u32);
//! assert_eq!(U32::declassify(x / y), 2);
//! ```
//!
//! Since indexing arrays and vectors is only possible with `usize`, these secret integers also
//! prevent you from using secret values to index memory (which is a breach to constant-timedness
//! due to cache behaviour).
//!
//! ```
//! # use secret_integers::*;
//! fn xor_block(block1: &mut [U64;16], block2: &[U64;16]) {
//!    for i in 0..16 {
//!      block1[i] ^= block2[i]
//!    }
//! }
//! ```
//!
//! # Const-compatibility
//!
//! Because stable Rust does not allow constant functions for now, it is impossible to use those
//! wrappers in const declarations. Even classifying directly inside the declaration does not work:
//!
//! ```compile_fail
//! const IV : [U32;2] = [U32::classify(0xbe6548u32),U32::classify(0xaec6d48u32)]
//! ```
//!
//! For now, the solution is to map your const items with `classify` once you're inside a function:
//!
//! ```
//! # use secret_integers::*;
//! const IV : [u32;2] = [0xbe6548, 0xaec6d48];
//!
//! fn start_cipher(plain: &mut Vec<U32>) {
//!    for i in 0..plain.len() {
//!      plain[i] |= plain[i] ^ U32::classify(IV[i]);
//!    }
//! }
//! ```
//!



use std::num::Wrapping;
use std::ops::*;

macro_rules! define_wrapping_op {
    ($name:ident, $op:tt, $op_name:ident, $func_op:ident, $assign_name:ident, $assign_func:ident) => {

        /// **Warning:** has wrapping semantics.
        impl $op_name for $name {
            type Output = Self;
            #[inline]
            fn $func_op(self, rhs: Self) -> Self {
                let $name(i1) = self;
                let $name(i2) = rhs;
                $name((Wrapping(i1) $op Wrapping(i2)).0)
            }
        }

        /// **Warning:** has wrapping semantics.
        impl $assign_name for $name {
            #[inline]
            fn $assign_func(&mut self, rhs: Self) {
                *self = *self $op rhs
            }
        }
    }
}

macro_rules! define_bitwise_op {
    ($name:ident, $op:tt, $op_name:ident, $func_op:ident, $assign_name:ident, $assign_func:ident) => {
        impl $op_name for $name {
            type Output = Self;
            #[inline]
            fn $func_op(self, rhs: Self) -> Self {
                let $name(i1) = self;
                let $name(i2) = rhs;
                $name(i1 $op i2)
            }
        }

        impl $assign_name for $name {
            #[inline]
            fn $assign_func(&mut self, rhs: Self) {
                *self = *self $op rhs
            }
        }
    }
}

macro_rules! define_unary_op {
    ($name:ident, $op:tt, $op_name:ident, $func_op:ident) => {
        impl $op_name for $name {
            type Output = Self;
            #[inline]
            fn $func_op(self) -> Self {
                let $name(i1) = self;
                $name($op i1)
            }
        }
    }
}

macro_rules! define_shift {
    ($name:ident, $op:tt, $op_name:ident, $func_op:ident, $assign_name:ident, $assign_func:ident) => {
        impl $op_name<u32> for $name {
            type Output = Self;
            #[inline]
            fn $func_op(self, rhs: u32) -> Self {
                let $name(i1) = self;
                $name(i1 $op rhs)
            }
        }

        impl $assign_name<u32> for $name {
            #[inline]
            fn $assign_func(&mut self, rhs: u32) {
                *self = *self $op rhs
            }
        }
    }
}

macro_rules! define_secret_integer {
    ($name:ident, $repr:ty, $bits:tt) => {
        #[derive(Clone, Copy, Default)]
        pub struct $name(pub(crate) $repr);

        impl $name {
            pub fn classify<T : Into<$repr>>(x: T) -> Self {
                $name(x.into())
            }

            /// **Warning:** use with caution, breaks the constant-time guarantee.
            pub fn declassify(self) -> $repr {
                self.0
            }

            pub fn zero() -> Self {
                $name(0)
            }

            pub fn one() -> Self {
                $name(1)
            }
        }

        define_wrapping_op!($name, +, Add, add, AddAssign, add_assign);
        define_wrapping_op!($name, -, Sub, sub, SubAssign, sub_assign);
        define_wrapping_op!($name, *, Mul, mul, MulAssign, mul_assign);

        define_shift!($name, <<, Shl, shl, ShlAssign, shl_assign);
        define_shift!($name, >>, Shr, shr, ShrAssign, shr_assign);

        impl $name {
            pub fn rotate_left(self, rotval:u32) -> Self {
                let $name(i) = self;
                $name(i.rotate_left(rotval))
            }

            pub fn rotate_right(self, rotval:u32) -> Self {
                let $name(i) = self;
                $name(i.rotate_right(rotval))
            }
        }

        define_bitwise_op!($name, &, BitAnd, bitand, BitAndAssign, bitand_assign);
        define_bitwise_op!($name, |, BitOr, bitor, BitOrAssign, bitor_assign);
        define_bitwise_op!($name, ^, BitXor, bitxor, BitXorAssign, bitxor_assign);
        define_unary_op!($name, !, Not, not);
    }
}

macro_rules! define_secret_unsigned_integer {
    ($name:ident, $repr:ty, $bits:tt) => {
        /// Secret unsigned integer.
        define_secret_integer!($name, $repr, $bits);
        impl Neg for $name {
            type Output = Self;
            #[inline]
            fn neg(self) -> Self {
                let $name(i1) = self;
                $name((Wrapping(!i1) + Wrapping(1)).0)
            }
        }
        impl $name {
            /// Produces a new integer which is all ones if the two arguments are equal and
            /// all zeroes otherwise. With inspiration from
            /// [Wireguard](https://git.zx2c4.com/WireGuard/commit/src/crypto/curve25519-hacl64.h?id=2e60bb395c1f589a398ec606d611132ef9ef764b).
            pub fn eq_mask(self, rhs: Self) -> Self {
                let a = self; let b = rhs;
                let x = a | b;
                let minus_x = - x;
                let x_or_minus_x = x | minus_x;
                let xnx = x_or_minus_x >> ($bits - 1);
                let c = xnx - Self::one();
                c
            }

            /// Produces a new integer which is all ones if the first argument is greater than or
            /// equal to the second argument, and all zeroes otherwise. With inspiration from
            /// [WireGuard](https://git.zx2c4.com/WireGuard/commit/src/crypto/curve25519-hacl64.h?id=0a483a9b431d87eca1b275463c632f8d5551978a).
            pub fn gte_mask(self, rhs: Self) -> Self {
                let x = self; let y = rhs;
                let x_xor_y = x | y;
                let x_sub_y = x - y;
                let x_sub_y_xor_y = x_sub_y ^ y;
                let q = x_xor_y ^ x_sub_y_xor_y;
                let x_xor_q = x ^ q;
                let x_xor_q_ = x_xor_q >> ($bits - 1 );
                let c = x_xor_q_ - Self::one();
                c
            }
        }
    };
}

macro_rules! define_secret_signed_integer {
    ($name:ident, $repr:ty, $bits:tt) => {
        /// Secret signed integer.
        define_secret_integer!($name, $repr, $bits);
        define_unary_op!($name, -, Neg, neg);
    }
}

define_secret_unsigned_integer!(U8, u8, 8);
define_secret_unsigned_integer!(U16, u16, 16);
define_secret_unsigned_integer!(U32, u32, 32);
define_secret_unsigned_integer!(U64, u64, 64);
define_secret_unsigned_integer!(U128, u128, 128);
define_secret_signed_integer!(I8, i8, 8);
define_secret_signed_integer!(I16, i16, 16);
define_secret_signed_integer!(I32, i32, 32);
define_secret_signed_integer!(I64, i64, 64);
define_secret_signed_integer!(I128, i128, 128);
