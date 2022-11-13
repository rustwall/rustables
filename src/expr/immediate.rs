use super::{Expression, Register, VerdictAttribute};
use crate::{create_expr_type, sys};

create_expr_type!(
  nested with_builder : ImmediateData,
    [
        (
            get_value,
            set_value,
            with_value,
            sys::NFTA_DATA_VALUE,
            VecU8,
            Vec<u8>
        ),
        (
            get_verdict,
            set_verdict,
            with_verdict,
            sys::NFTA_DATA_VERDICT,
            ExprVerdictAttribute,
            VerdictAttribute
        )
    ]
);

create_expr_type!(
    inline with_builder : Immediate,
    [
        (
            get_dreg,
            set_dreg,
            with_dreg,
            sys::NFTA_IMMEDIATE_DREG,
            Register,
            Register
        ),
        (
            get_data,
            set_data,
            with_data,
            sys::NFTA_IMMEDIATE_DATA,
            ExprImmediateData,
            ImmediateData
        )
    ]
);

impl Immediate {
    pub fn new_data(data: Vec<u8>, register: Register) -> Self {
        Immediate::builder()
            .with_dreg(register)
            .with_data(ImmediateData::builder().with_value(data))
    }
}

impl Expression for Immediate {
    fn get_name() -> &'static str {
        "immediate"
    }
}
