use super::{DeserializationError, Expression, Register, Rule, ToSlice};
use rustables_sys as sys;
use std::ffi::c_void;
use std::os::raw::c_char;

/// An immediate expression. Used to set immediate data.
/// Verdicts are handled separately by [crate::expr::Verdict].
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

            let data = self.data.to_slice();
            sys::nftnl_expr_set(
                expr,
                sys::NFTNL_EXPR_IMM_DATA as u16,
                data.as_ptr() as *const c_void,
                data.len() as u32,
            );

            expr
        }
    }
}

impl<const N: usize> Expression for Immediate<[u8; N]> {
    fn get_raw_name() -> *const c_char {
        Immediate::<u8>::get_raw_name()
    }

    /// The raw data contained inside `Immediate` expressions can only be deserialized to
    /// arrays of bytes, to ensure that the memory layout of retrieved data cannot be
    /// violated. It is your responsibility to provide the correct length of the byte
    /// data. If the data size is invalid, you will get the error
    /// `DeserializationError::InvalidDataSize`.
    ///
    /// Example (warning, no error checking!):
    /// ```rust
    /// use std::ffi::CString;
    /// use std::net::Ipv4Addr;
    /// use std::rc::Rc;
    ///
    /// use rustables::{Chain, expr::{Immediate, Register}, ProtoFamily, Rule, Table};
    ///
    /// let table = Rc::new(Table::new(&CString::new("mytable").unwrap(), ProtoFamily::Inet));
    /// let chain = Rc::new(Chain::new(&CString::new("mychain").unwrap(), table));
    /// let mut rule = Rule::new(chain);
    /// rule.add_expr(&Immediate::new(42u8, Register::Reg1));
    /// for expr in Rc::new(rule).get_exprs() {
    ///     println!("{:?}", expr.decode_expr::<Immediate<[u8; 1]>>().unwrap());
    /// }
    /// ```
    /// These limitations occur because casting bytes to any type of the same size
    /// as the raw input would be *extremely* dangerous in terms of memory safety.
    // As casting bytes to any type of the same size as the input would
    // be *extremely* dangerous in terms of memory safety,
    // rustables only accept to deserialize expressions with variable-size data
    // to arrays of bytes, so that the memory layout cannot be invalid.
    fn from_expr(expr: *const sys::nftnl_expr) -> Result<Self, DeserializationError> {
        unsafe {
            let ref_len = std::mem::size_of::<[u8; N]>() as u32;
            let mut data_len = 0;
            let data = sys::nftnl_expr_get(
                expr,
                sys::NFTNL_EXPR_IMM_DATA as u16,
                &mut data_len as *mut u32,
            );

            if data.is_null() {
                return Err(DeserializationError::NullPointer);
            } else if data_len != ref_len {
                return Err(DeserializationError::InvalidDataSize);
            }

            let data = *(data as *const [u8; N]);

            let register = Register::from_raw(sys::nftnl_expr_get_u32(
                expr,
                sys::NFTNL_EXPR_IMM_DREG as u16,
            ))?;

            Ok(Immediate { data, register })
        }
    }

    // call to the other implementation to generate the expression
    fn to_expr(&self, rule: &Rule) -> *mut sys::nftnl_expr {
        Immediate {
            register: self.register,
            data: &self.data as &[u8],
        }
        .to_expr(rule)
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
