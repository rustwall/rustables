use super::{Expression, ExpressionData, Register};
use crate::{create_expr_type, sys};

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
            ExprData,
            ExpressionData
        )
    ]
);

impl Immediate {
    pub fn new_data(data: Vec<u8>, register: Register) -> Self {
        Immediate::builder()
            .with_dreg(register)
            .with_data(ExpressionData::builder().with_value(data))
    }
}

impl Expression for Immediate {
    fn get_name() -> &'static str {
        "immediate"
    }
}
