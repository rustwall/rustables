use rustables_macros::nfnetlink_struct;

use super::{Expression, ExpressionData, Register};
use crate::sys::{NFTA_IMMEDIATE_DATA, NFTA_IMMEDIATE_DREG};

#[derive(Clone, PartialEq, Eq, Default, Debug)]
#[nfnetlink_struct]
pub struct Immediate {
    #[field(NFTA_IMMEDIATE_DREG)]
    dreg: Register,
    #[field(NFTA_IMMEDIATE_DATA)]
    data: ExpressionData,
}

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
