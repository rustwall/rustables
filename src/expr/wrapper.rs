use std::ffi::CStr;
use std::ffi::CString;
use std::fmt::Debug;
use std::rc::Rc;

use super::{DeserializationError, Expression};
use crate::{sys, Rule};

pub struct ExpressionWrapper {
    pub(crate) expr: *const sys::nftnl_expr,
    // we also need the rule here to ensure that the rule lives as long as the `expr` pointer
    #[allow(dead_code)]
    pub(crate) rule: Rc<Rule>,
}

impl Debug for ExpressionWrapper {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.get_str())
    }
}

impl ExpressionWrapper {
    /// Retrieves a textual description of the expression.
    pub fn get_str(&self) -> CString {
        let mut descr_buf = vec![0i8; 4096];
        unsafe {
            sys::nftnl_expr_snprintf(
                descr_buf.as_mut_ptr(),
                (descr_buf.len() - 1) as u64,
                self.expr,
                sys::NFTNL_OUTPUT_DEFAULT,
                0,
            );
            CStr::from_ptr(descr_buf.as_ptr()).to_owned()
        }
    }

    /// Retrieves the type of expression ("log", "counter", ...).
    pub fn get_kind(&self) -> Option<&CStr> {
        unsafe {
            let ptr = sys::nftnl_expr_get_str(self.expr, sys::NFTNL_EXPR_NAME as u16);
            if !ptr.is_null() {
                Some(CStr::from_ptr(ptr))
            } else {
                None
            }
        }
    }

    /// Attempts to decode the expression as the type T.
    pub fn decode_expr<T: Expression>(&self) -> Result<T, DeserializationError> {
        if let Some(kind) = self.get_kind() {
            let raw_name = unsafe { CStr::from_ptr(T::get_raw_name()) };
            if kind == raw_name {
                return T::from_expr(self.expr);
            }
        }
        Err(DeserializationError::InvalidExpressionKind)
    }
}
