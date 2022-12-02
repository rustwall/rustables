use super::{Expression, ExpressionData, Register};
use crate::{create_wrapper_type, sys};

create_wrapper_type!(
    inline: Immediate,
    [
        (
            get_dreg,
            set_dreg,
            with_dreg,
            sys::NFTA_IMMEDIATE_DREG,
            dreg,
            Register
        ),
        (
            get_data,
            set_data,
            with_data,
            sys::NFTA_IMMEDIATE_DATA,
            data,
            ExpressionData
        )
    ]
);

impl Immediate {
    pub fn new_data(data: Vec<u8>, register: Register) -> Self {
        Immediate::default()
            .with_dreg(register)
            .with_data(ExpressionData::default().with_value(data))
    }
}

impl Expression for Immediate {
    fn get_name() -> &'static str {
        "immediate"
    }
}
