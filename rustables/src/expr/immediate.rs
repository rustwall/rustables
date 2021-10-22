use super::{Expression, Register, Rule};
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

// The Copy requirement is present to allow us to dereference the newly created raw pointer in `from_expr`
impl<T: Copy> Expression for Immediate<T> {
    fn get_raw_name() -> *const c_char {
        b"immediate\0" as *const _ as *const c_char
    }

    fn from_expr(expr: *const sys::nftnl_expr) -> Option<Self>
    where
        Self: Sized,
    {
        unsafe {
            let ref_len = std::mem::size_of::<T>() as u32;
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

            // Warning: this is *very* dangerous safety wise if the user supply us with
            // a type that have the same size as T but a different memory layout.
            // Is there a better way? And if there isn't, shouldn't we gate this behind
            // an "unsafe" boundary?
            let data = *(data as *const T);

            let register = Register::from_raw(sys::nftnl_expr_get_u32(
                expr,
                sys::NFTNL_EXPR_IMM_DREG as u16,
            ));

            register.map(|register| Immediate { data, register })
        }
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
                &self.data as *const _ as *const c_void,
                size_of_val(&self.data) as u32,
            );

            expr
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
