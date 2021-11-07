use super::{DeserializationError, Expression, Rule, ToSlice};
use crate::sys::{self, libc};
use std::{
    borrow::Cow,
    ffi::{c_void, CString},
    os::raw::c_char,
};

/// Comparison operator.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum CmpOp {
    /// Equals.
    Eq,
    /// Not equal.
    Neq,
    /// Less than.
    Lt,
    /// Less than, or equal.
    Lte,
    /// Greater than.
    Gt,
    /// Greater than, or equal.
    Gte,
}

impl CmpOp {
    /// Returns the corresponding `NFT_*` constant for this comparison operation.
    pub fn to_raw(self) -> u32 {
        use self::CmpOp::*;
        match self {
            Eq => libc::NFT_CMP_EQ as u32,
            Neq => libc::NFT_CMP_NEQ as u32,
            Lt => libc::NFT_CMP_LT as u32,
            Lte => libc::NFT_CMP_LTE as u32,
            Gt => libc::NFT_CMP_GT as u32,
            Gte => libc::NFT_CMP_GTE as u32,
        }
    }

    pub fn from_raw(val: u32) -> Result<Self, DeserializationError> {
        use self::CmpOp::*;
        match val as i32 {
            libc::NFT_CMP_EQ => Ok(Eq),
            libc::NFT_CMP_NEQ => Ok(Neq),
            libc::NFT_CMP_LT => Ok(Lt),
            libc::NFT_CMP_LTE => Ok(Lte),
            libc::NFT_CMP_GT => Ok(Gt),
            libc::NFT_CMP_GTE => Ok(Gte),
            _ => Err(DeserializationError::InvalidValue),
        }
    }
}

/// Comparator expression. Allows comparing the content of the netfilter register with any value.
#[derive(Debug, PartialEq)]
pub struct Cmp<T> {
    op: CmpOp,
    data: T,
}

impl<T: ToSlice> Cmp<T> {
    /// Returns a new comparison expression comparing the value loaded in the register with the
    /// data in `data` using the comparison operator `op`.
    pub fn new(op: CmpOp, data: T) -> Self {
        Cmp { op, data }
    }
}

impl<T: ToSlice> Expression for Cmp<T> {
    fn get_raw_name() -> *const c_char {
        b"cmp\0" as *const _ as *const c_char
    }

    fn to_expr(&self, _rule: &Rule) -> *mut sys::nftnl_expr {
        unsafe {
            let expr = try_alloc!(sys::nftnl_expr_alloc(Self::get_raw_name()));

            let data = self.data.to_slice();
            trace!("Creating a cmp expr comparing with data {:?}", data);

            sys::nftnl_expr_set_u32(
                expr,
                sys::NFTNL_EXPR_CMP_SREG as u16,
                libc::NFT_REG_1 as u32,
            );
            sys::nftnl_expr_set_u32(expr, sys::NFTNL_EXPR_CMP_OP as u16, self.op.to_raw());
            sys::nftnl_expr_set(
                expr,
                sys::NFTNL_EXPR_CMP_DATA as u16,
                data.as_ptr() as *const c_void,
                data.len() as u32,
            );

            expr
        }
    }
}

impl<const N: usize> Expression for Cmp<[u8; N]> {
    fn get_raw_name() -> *const c_char {
        Cmp::<u8>::get_raw_name()
    }

    /// The raw data contained inside `Cmp` expressions can only be deserialized to
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
    /// use rustables::{Chain, expr::{Cmp, CmpOp}, ProtoFamily, Rule, Table};
    ///
    /// let table = Rc::new(Table::new(&CString::new("mytable").unwrap(), ProtoFamily::Inet));
    /// let chain = Rc::new(Chain::new(&CString::new("mychain").unwrap(), table));
    /// let mut rule = Rule::new(chain);
    /// rule.add_expr(&Cmp::new(CmpOp::Eq, 1337u16));
    /// for expr in Rc::new(rule).get_exprs() {
    ///     println!("{:?}", expr.decode_expr::<Cmp<[u8; 2]>>().unwrap());
    /// }
    /// ```
    /// These limitations occur because casting bytes to any type of the same size
    /// as the raw input would be *extremely* dangerous in terms of memory safety.
    fn from_expr(expr: *const sys::nftnl_expr) -> Result<Self, DeserializationError> {
        unsafe {
            let ref_len = std::mem::size_of::<[u8; N]>() as u32;
            let mut data_len = 0;
            let data = sys::nftnl_expr_get(
                expr,
                sys::NFTNL_EXPR_CMP_DATA as u16,
                &mut data_len as *mut u32,
            );

            if data.is_null() {
                return Err(DeserializationError::NullPointer);
            } else if data_len != ref_len {
                return Err(DeserializationError::InvalidDataSize);
            }

            let data = *(data as *const [u8; N]);

            let op = CmpOp::from_raw(sys::nftnl_expr_get_u32(expr, sys::NFTNL_EXPR_CMP_OP as u16))?;
            Ok(Cmp { op, data })
        }
    }

    // call to the other implementation to generate the expression
    fn to_expr(&self, rule: &Rule) -> *mut sys::nftnl_expr {
        Cmp {
            data: &self.data as &[u8],
            op: self.op,
        }
        .to_expr(rule)
    }
}

#[macro_export(local_inner_macros)]
macro_rules! nft_expr_cmp {
    (@cmp_op ==) => {
        $crate::expr::CmpOp::Eq
    };
    (@cmp_op !=) => {
        $crate::expr::CmpOp::Neq
    };
    (@cmp_op <) => {
        $crate::expr::CmpOp::Lt
    };
    (@cmp_op <=) => {
        $crate::expr::CmpOp::Lte
    };
    (@cmp_op >) => {
        $crate::expr::CmpOp::Gt
    };
    (@cmp_op >=) => {
        $crate::expr::CmpOp::Gte
    };
    ($op:tt $data:expr) => {
        $crate::expr::Cmp::new(nft_expr_cmp!(@cmp_op $op), $data)
    };
}

/// Can be used to compare the value loaded by [`Meta::IifName`] and [`Meta::OifName`]. Please
/// note that it is faster to check interface index than name.
///
/// [`Meta::IifName`]: enum.Meta.html#variant.IifName
/// [`Meta::OifName`]: enum.Meta.html#variant.OifName
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub enum InterfaceName {
    /// Interface name must be exactly the value of the `CString`.
    Exact(CString),
    /// Interface name must start with the value of the `CString`.
    ///
    /// `InterfaceName::StartingWith("eth")` will look like `eth*` when printed and match against
    /// `eth0`, `eth1`, ..., `eth99` and so on.
    StartingWith(CString),
}

impl ToSlice for InterfaceName {
    fn to_slice(&self) -> Cow<'_, [u8]> {
        let bytes = match *self {
            InterfaceName::Exact(ref name) => name.as_bytes_with_nul(),
            InterfaceName::StartingWith(ref name) => name.as_bytes(),
        };
        Cow::from(bytes)
    }
}

impl<'a> ToSlice for &'a InterfaceName {
    fn to_slice(&self) -> Cow<'_, [u8]> {
        let bytes = match *self {
            InterfaceName::Exact(ref name) => name.as_bytes_with_nul(),
            InterfaceName::StartingWith(ref name) => name.as_bytes(),
        };
        Cow::from(bytes)
    }
}
