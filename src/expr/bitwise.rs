use super::{Expression, ExpressionData, Register};
use crate::create_expr_type;
use crate::parser::DecodeError;
use crate::sys;

create_expr_type!(
    inline with_builder : Bitwise,
    [
        (
            get_dreg,
            set_dreg,
            with_dreg,
            sys::NFTA_BITWISE_DREG,
            Register,
            Register
        ),
        (
            get_sreg,
            set_sreg,
            with_sreg,
            sys::NFTA_BITWISE_SREG,
            Register,
            Register
        ),
        (
            get_len,
            set_len,
            with_len,
            sys::NFTA_BITWISE_LEN,
            U32,
            u32
        ),
        (
            get_mask,
            set_mask,
            with_mask,
            sys::NFTA_BITWISE_MASK,
            ExprData,
            ExpressionData
        ),
        (
            get_xor,
            set_xor,
            with_xor,
            sys::NFTA_BITWISE_XOR,
            ExprData,
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
        Ok(Self::builder()
            .with_sreg(Register::Reg1)
            .with_dreg(Register::Reg1)
            .with_len(mask.len() as u32)
            .with_xor(ExpressionData::builder().with_value(xor))
            .with_mask(ExpressionData::builder().with_value(mask)))
    }
}
