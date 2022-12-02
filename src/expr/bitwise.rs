use super::{Expression, ExpressionData, Register};
use crate::create_wrapper_type;
use crate::parser::DecodeError;
use crate::sys;

create_wrapper_type!(
    inline: Bitwise,
    [
        (
            get_sreg,
            set_sreg,
            with_sreg,
            sys::NFTA_BITWISE_SREG,
            sreg,
            Register
        ),
        (
            get_dreg,
            set_dreg,
            with_dreg,
            sys::NFTA_BITWISE_DREG,
            dreg,
            Register
        ),
        (get_len, set_len, with_len, sys::NFTA_BITWISE_LEN, len, u32),
        (
            get_mask,
            set_mask,
            with_mask,
            sys::NFTA_BITWISE_MASK,
            mask,
            ExpressionData
        ),
        (
            get_xor,
            set_xor,
            with_xor,
            sys::NFTA_BITWISE_XOR,
            xor,
            ExpressionData
        )
    ]
);

impl Expression for Bitwise {
    fn get_name() -> &'static str {
        "bitwise"
    }
}

impl Bitwise {
    /// Returns a new `Bitwise` instance that first masks the value it's applied to with `mask` and
    /// then performs xor with the value in `xor`
    pub fn new(mask: impl Into<Vec<u8>>, xor: impl Into<Vec<u8>>) -> Result<Self, DecodeError> {
        let mask = mask.into();
        let xor = xor.into();
        if mask.len() != xor.len() {
            return Err(DecodeError::IncompatibleLength);
        }
        Ok(Bitwise::default()
            .with_sreg(Register::Reg1)
            .with_dreg(Register::Reg1)
            .with_len(mask.len() as u32)
            .with_xor(ExpressionData::default().with_value(xor))
            .with_mask(ExpressionData::default().with_value(mask)))
    }
}
