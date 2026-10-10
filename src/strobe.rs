//! Minimal implementation of (parts of) Strobe.

use core::{convert::TryInto, ops::{Deref, DerefMut}};

use keccak::Keccak;
use zeroize::Zeroize;

/// Strobe R value; security level 128 is hardcoded
const STROBE_R: u8 = 166;

/// Length of the strobe context in bytes
pub const STROBE_LENGTH: usize = 203;

const FLAG_I: u8 = 1;
const FLAG_A: u8 = 1 << 1;
const FLAG_C: u8 = 1 << 2;
const FLAG_T: u8 = 1 << 3;
const FLAG_M: u8 = 1 << 4;
const FLAG_K: u8 = 1 << 5;

fn transmute_state(st: &mut AlignedKeccakState) -> &mut [u64; 25] {
    let byte_slice: &mut [u8] = &mut st.0; 
    
    // Cast the byte slice to a slice of u64s
    // Verifies length and alignment at runtime.
    let u64_slice: &mut [u64] = bytemuck::cast_slice_mut(byte_slice);
        
    // Turn the slice back into a fixed array reference
    u64_slice.try_into().unwrap()
}

/// This is a wrapper around 200-byte buffer that's always 8-byte aligned
/// to make pointers to it safely convertible to pointers to [u64; 25]
/// (since u64 words must be 8-byte aligned)
#[cfg_attr(test, derive(PartialEq))]

#[derive(Clone, Zeroize)]
#[zeroize(drop)]
#[repr(align(8))]
struct AlignedKeccakState([u8; 200]);

/// A Strobe context for the 128-bit security level.
///
/// Only `meta-AD`, `AD`, `KEY`, and `PRF` operations are supported.
#[cfg_attr(test, derive(PartialEq))]

#[derive(Clone, Zeroize)]
pub struct Strobe128 {
    state: AlignedKeccakState,
    pos: u8,
    pos_begin: u8,
    cur_flags: u8,
}

impl ::core::fmt::Debug for Strobe128 {
    fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
        // Ensure that the Strobe state isn't accidentally logged
        write!(f, "Strobe128: STATE OMITTED")
    }
}

impl Strobe128 {
    pub fn new(protocol_label: &[u8]) -> Strobe128 {
        let initial_state = {
            let mut st = AlignedKeccakState([0u8; 200]);
            st[0..6].copy_from_slice(&[1, STROBE_R + 2, 1, 0, 1, 96]);
            st[6..18].copy_from_slice(b"STROBEv1.0.2");
            Keccak::new().with_f1600(|f1600| {
                f1600(transmute_state(&mut st))
            });

            st
        };

        let mut strobe = Strobe128 {
            state: initial_state,
            pos: 0,
            pos_begin: 0,
            cur_flags: 0,
        };

        strobe.meta_ad(protocol_label, false);

        strobe
    }

    pub fn meta_ad(&mut self, data: &[u8], more: bool) {
        self.begin_op(FLAG_M | FLAG_A, more);
        self.absorb(data);
    }

    pub fn ad(&mut self, data: &[u8], more: bool) {
        self.begin_op(FLAG_A, more);
        self.absorb(data);
    }

    pub fn prf(&mut self, data: &mut [u8], more: bool) {
        self.begin_op(FLAG_I | FLAG_A | FLAG_C, more);
        self.squeeze(data);
    }

    pub fn key(&mut self, data: &[u8], more: bool) {
        self.begin_op(FLAG_A | FLAG_C, more);
        self.overwrite(data);
    }

    /// Convert the strobe context into a byte array
    /// 
    /// **Warning**: Do not use this for logging, it reveals the strobe state
    pub fn as_bytes(&self) -> [u8; STROBE_LENGTH]{
        let mut bytes = [0u8; STROBE_LENGTH];
        
        bytes[0..200].copy_from_slice(&*self.state);
        bytes[200..201].copy_from_slice(&self.pos.to_le_bytes());
        bytes[201..202].copy_from_slice(&self.pos_begin.to_le_bytes());
        bytes[202..203].copy_from_slice(&self.cur_flags.to_le_bytes());

        return bytes
    }

    /// Convert bytes into a Strobe context, [`Strobe128`]
    /// 
    /// **Warning**: Only call this method if the source of the bytes can be trusted
    /// 
    /// Otherwise, prefer recreating the Strobe with [`Strobe128::new()`]
    pub fn from_bytes(bytes: [u8; STROBE_LENGTH]) -> Strobe128{
        let mut state = [0u8; 200];
        state.copy_from_slice(&bytes[0..200]);

        let pos = bytes[200];
        let pos_begin = bytes[201];
        let cur_flags = bytes[202];

        Strobe128 {
            state: AlignedKeccakState(state), 
            pos, 
            pos_begin, 
            cur_flags 
        }
    }
}

impl Strobe128 {
    fn run_f(&mut self) {
        self.state[self.pos as usize] ^= self.pos_begin;
        self.state[(self.pos + 1) as usize] ^= 0x04;
        self.state[(STROBE_R + 1) as usize] ^= 0x80;
        Keccak::new().with_f1600(|f1600| {
            f1600(transmute_state(&mut self.state))
        });
        self.pos = 0;
        self.pos_begin = 0;
    }

    fn absorb(&mut self, data: &[u8]) {
        for byte in data {
            self.state[self.pos as usize] ^= byte;
            self.pos += 1;
            if self.pos == STROBE_R {
                self.run_f();
            }
        }
    }

    fn overwrite(&mut self, data: &[u8]) {
        for byte in data {
            self.state[self.pos as usize] = *byte;
            self.pos += 1;
            if self.pos == STROBE_R {
                self.run_f();
            }
        }
    }

    fn squeeze(&mut self, data: &mut [u8]) {
        for byte in data {
            *byte = self.state[self.pos as usize];
            self.state[self.pos as usize] = 0;
            self.pos += 1;
            if self.pos == STROBE_R {
                self.run_f();
            }
        }
    }

    fn begin_op(&mut self, flags: u8, more: bool) {
        // Check if we're continuing an operation
        if more {
            assert_eq!(
                self.cur_flags, flags,
                "You tried to continue op {:#b} but changed flags to {:#b}",
                self.cur_flags, flags,
            );
            return;
        }

        // Skip adjusting direction information (we just use AD, PRF)
        assert_eq!(
            flags & FLAG_T,
            0u8,
            "You used the T flag, which this implementation doesn't support"
        );

        let old_begin = self.pos_begin;
        self.pos_begin = self.pos + 1;
        self.cur_flags = flags;

        self.absorb(&[old_begin, flags]);

        // Force running F if C or K is set
        let force_f = 0 != (flags & (FLAG_C | FLAG_K));

        if force_f && self.pos != 0 {
            self.run_f();
        }
    }
}

impl Deref for AlignedKeccakState {
    type Target = [u8; 200];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for AlignedKeccakState {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytemuck::PodCastError;
    use strobe_rs::{self, SecParam};

    #[test]
    fn test_conformance() {
        let mut s1 = super::Strobe128::new(b"Conformance Test Protocol");
        let mut s2 = strobe_rs::Strobe::new(b"Conformance Test Protocol", SecParam::B128);

        // meta-AD(b"msg"); AD(msg)

        let msg = [99u8; 1024];

        s1.meta_ad(b"ms", false);
        s1.meta_ad(b"g", true);
        s1.ad(&msg, false);

        s2.meta_ad(b"ms", false);
        s2.meta_ad(b"g", true);
        s2.ad(&msg, false);

        // meta-AD(b"prf"); PRF()

        let mut prf1 = [0u8; 32];
        s1.meta_ad(b"prf", false);
        s1.prf(&mut prf1, false);

        let mut prf2 = [0u8; 32];
        s2.meta_ad(b"prf", false);
        s2.prf(&mut prf2, false);

        assert_eq!(prf1, prf2);

        // meta-AD(b"key"); KEY(prf output)

        s1.meta_ad(b"key", false);
        s1.key(&prf1, false);

        s2.meta_ad(b"key", false);
        s2.key(&prf2, false);

        // meta-AD(b"prf"); PRF()

        let mut prf1 = [0u8; 32];
        s1.meta_ad(b"prf", false);
        s1.prf(&mut prf1, false);

        let mut prf2 = [0u8; 32];
        s2.meta_ad(b"prf", false);
        s2.prf(&mut prf2, false);

        assert_eq!(prf1, prf2);
    }
    #[test]
    fn test_bytemuck_runtime_enforcement() {
        // Create a properly aligned instance
        let mut state = AlignedKeccakState([0u8; 200]);
        
        // This must succeed because size is exactly 200 bytes and alignment is 8
        transmute_state(&mut state.clone());

        let byte_slice: &mut [u8] = &mut state.0;

        // Create a slice that is 199 bytes instead of 200 (not divisible by 8)
        let mismatched_size_slice = &mut byte_slice[..199];
        let size_error = bytemuck::try_cast_slice_mut::<u8, u64>(mismatched_size_slice);
        
        // This will fail with an OutputSliceWouldHaveSlop
        assert_eq!(size_error.unwrap_err(), PodCastError::OutputSliceWouldHaveSlop);

        // Create an unaligned slice by offsetting the start pointer by exactly 1 byte.
        // Even though 192 bytes is divisible by 8 (24 elements), the memory address 
        // itself is now misaligned (Address % 8 != 0).
        let misaligned_slice = &mut byte_slice[1..193]; 
        let align_error = bytemuck::try_cast_slice_mut::<u8, u64>(misaligned_slice);

        // This will fail with a TargetAlignmentGreaterAndInputNotAligned error
        assert_eq!(align_error.unwrap_err(), PodCastError::TargetAlignmentGreaterAndInputNotAligned);
    }

    #[test]
    fn test_strobe_bytes(){
        let strobe = Strobe128::new(b"Strobe Bytes Test");

        // Rebuild the strobe from the raw bytes
        let valid_bytes = strobe.as_bytes();
        let reconstructed_strobe = Strobe128::from_bytes(valid_bytes);

        assert_eq!(strobe, reconstructed_strobe);

        // Create an invalid strobe
        let invalid_bytes = [0u8; 203];
        let invalid_strobe = Strobe128::from_bytes(invalid_bytes);

        assert_ne!(strobe, invalid_strobe);
    }
}
