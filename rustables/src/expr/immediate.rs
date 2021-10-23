use super::{Expression, Register, Rule, ToSlice};
use rustables_sys as sys;
use std::ffi::c_void;
use std::mem::size_of_val;
use std::os::raw::c_char;

/// An immediate expression. Used to set immediate data.
/// Verdicts are handled separately by [Verdict].
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct Immediate<T> {
    pub data: T,
    pub register: Register,
}

impl<T> Immediate<T> {
    pub fn new(data: T, register: Register) -> Self {
        Self { data, register }
    }
}

impl<T: ToSlice> Expression for Immediate<T> {
    fn get_raw_name() -> *const c_char {
        b"immediate\0" as *const _ as *const c_char
    }

    fn to_expr(&self, _rule: &Rule) -> *mut sys::nftnl_expr {
        unsafe {
            let expr = try_alloc!(sys::nftnl_expr_alloc(Self::get_raw_name()));

            sys::nftnl_expr_set_u32(
                expr,
                sys::NFTNL_EXPR_IMM_DREG as u16,
                self.register.to_raw(),
            );

            sys::nftnl_expr_set(
                expr,
                sys::NFTNL_EXPR_IMM_DATA as u16,
                &self.data.to_slice() as *const _ as *const c_void,
                size_of_val(&self.data) as u32,
            );

            expr
        }
    }
}

impl<const N: usize> Expression for Immediate<[u8; N]> {
    fn get_raw_name() -> *const c_char {
        Immediate::<u8>::get_raw_name()
    }

    // As casting bytes to any type of the same size as the input would
    // be *extremely* dangerous in terms of memory safety,
    // rustables only accept to deserialize expressions with variable-size data
    // to arrays of bytes, so that the memory layout cannot be invalid.
    fn from_expr(expr: *const sys::nftnl_expr) -> Option<Self> {
        unsafe {
            let ref_len = std::mem::size_of::<[u8; N]>() as u32;
            let mut data_len = 0;
            let data = sys::nftnl_expr_get(
                expr,
                sys::NFTNL_EXPR_IMM_DATA as u16,
                &mut data_len as *mut u32,
            );

            if data.is_null() {
                return None;
            } else if data_len != ref_len {
                debug!("Invalid size requested for deserializing an 'immediate' expression: expected {} bytes, got {}", ref_len, data_len);
                return None;
            }

            let data = *(data as *const [u8; N]);

            let register = Register::from_raw(sys::nftnl_expr_get_u32(
                expr,
                sys::NFTNL_EXPR_IMM_DREG as u16,
            ));

            register.map(|register| Immediate { data, register })
        }
    }

    // call to the other implementation to generate the expression
    fn to_expr(&self, rule: &Rule) -> *mut sys::nftnl_expr {
        Immediate {
            register: self.register,
            data: self.data.as_ref(),
        }
        .to_expr(rule)
    }
}
// As casting bytes to any type of the same size as the input would
// be *extremely* dangerous in terms of memory safety,
// rustables only accept to deserialize expressions with variable-size data
// to arrays of bytes, so that the memory layout cannot be invalid.
impl<const N: usize> Immediate<[u8; N]> {
    pub fn from_expr(expr: *const sys::nftnl_expr) -> Option<Self> {
        unsafe {
            let ref_len = std::mem::size_of::<[u8; N]>() as u32;
            let mut data_len = 0;
            let data = sys::nftnl_expr_get(
                expr,
                sys::NFTNL_EXPR_IMM_DATA as u16,
                &mut data_len as *mut u32,
            );

            if data.is_null() {
                return None;
            } else if data_len != ref_len {
                debug!("Invalid size requested for deserializing an 'immediate' expression: expected {} bytes, got {}", ref_len, data_len);
                return None;
            }

            let data = *(data as *const [u8; N]);

            let register = Register::from_raw(sys::nftnl_expr_get_u32(
                expr,
                sys::NFTNL_EXPR_IMM_DREG as u16,
            ));

            register.map(|register| Immediate { data, register })
        }
    }
}

#[macro_export]
macro_rules! nft_expr_immediate {
    (data $value:expr) => {
        $crate::expr::Immediate {
            data: $value,
            register: $crate::expr::Register::Reg1,
        }
    };
}
