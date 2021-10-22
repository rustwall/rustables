use super::{Expression, Rule};
use rustables_sys::{self as sys, libc};
use std::{
    borrow::Cow,
    ffi::{c_void, CString},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    os::raw::c_char,
    slice,
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

    pub fn from_raw(val: u32) -> Option<Self> {
        use self::CmpOp::*;
        match val as i32 {
            libc::NFT_CMP_EQ => Some(Eq),
            libc::NFT_CMP_NEQ => Some(Neq),
            libc::NFT_CMP_LT => Some(Lt),
            libc::NFT_CMP_LTE => Some(Lte),
            libc::NFT_CMP_GT => Some(Gt),
            libc::NFT_CMP_GTE => Some(Gte),
            _ => None,
        }
    }
}

/// Comparator expression. Allows comparing the content of the netfilter register with any value.
#[derive(Debug, PartialEq)]
pub struct Cmp<T: ToSlice> {
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

impl<T: ToSlice + Copy> Expression for Cmp<T> {
    fn get_raw_name() -> *const c_char {
        b"cmp\0" as *const _ as *const c_char
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
                sys::NFTNL_EXPR_CMP_DATA as u16,
                &mut data_len as *mut u32,
            );

            if data.is_null() {
                return None;
            } else if data_len != ref_len {
                debug!("Invalid size requested for deserializing a 'cmp' expression: expected {} bytes, got {}", ref_len, data_len);
                return None;
            }

            // Warning: this is *very* dangerous safety wise if the user supply us with
            // a type that have the same size as T but a different memory layout.
            // Is there a better way? And if there isn't, shouldn't we gate this behind
            // an "unsafe" boundary?
            let data = *(data as *const T);

            let op = CmpOp::from_raw(sys::nftnl_expr_get_u32(expr, sys::NFTNL_EXPR_CMP_OP as u16));
            op.map(|op| Cmp { op, data })
        }
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
                data.as_ref() as *const _ as *const c_void,
                data.len() as u32,
            );

            expr
        }
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

/// A type that can be converted into a byte buffer.
pub trait ToSlice {
    /// Returns the data this type represents.
    fn to_slice(&self) -> Cow<'_, [u8]>;
}

impl<'a> ToSlice for [u8; 0] {
    fn to_slice(&self) -> Cow<'_, [u8]> {
        Cow::Borrowed(&[])
    }
}

impl<'a> ToSlice for &'a [u8] {
    fn to_slice(&self) -> Cow<'_, [u8]> {
        Cow::Borrowed(self)
    }
}

impl<'a> ToSlice for &'a [u16] {
    fn to_slice(&self) -> Cow<'_, [u8]> {
        let ptr = self.as_ptr() as *const u8;
        let len = self.len() * 2;
        Cow::Borrowed(unsafe { slice::from_raw_parts(ptr, len) })
    }
}

impl ToSlice for IpAddr {
    fn to_slice(&self) -> Cow<'_, [u8]> {
        match *self {
            IpAddr::V4(ref addr) => addr.to_slice(),
            IpAddr::V6(ref addr) => addr.to_slice(),
        }
    }
}

impl ToSlice for Ipv4Addr {
    fn to_slice(&self) -> Cow<'_, [u8]> {
        Cow::Owned(self.octets().to_vec())
    }
}

impl ToSlice for Ipv6Addr {
    fn to_slice(&self) -> Cow<'_, [u8]> {
        Cow::Owned(self.octets().to_vec())
    }
}

impl ToSlice for u8 {
    fn to_slice(&self) -> Cow<'_, [u8]> {
        Cow::Owned(vec![*self])
    }
}

impl ToSlice for u16 {
    fn to_slice(&self) -> Cow<'_, [u8]> {
        let b0 = (*self & 0x00ff) as u8;
        let b1 = (*self >> 8) as u8;
        Cow::Owned(vec![b0, b1])
    }
}

impl ToSlice for u32 {
    fn to_slice(&self) -> Cow<'_, [u8]> {
        let b0 = *self as u8;
        let b1 = (*self >> 8) as u8;
        let b2 = (*self >> 16) as u8;
        let b3 = (*self >> 24) as u8;
        Cow::Owned(vec![b0, b1, b2, b3])
    }
}

impl ToSlice for i32 {
    fn to_slice(&self) -> Cow<'_, [u8]> {
        let b0 = *self as u8;
        let b1 = (*self >> 8) as u8;
        let b2 = (*self >> 16) as u8;
        let b3 = (*self >> 24) as u8;
        Cow::Owned(vec![b0, b1, b2, b3])
    }
}

impl<'a> ToSlice for &'a str {
    fn to_slice(&self) -> Cow<'_, [u8]> {
        Cow::from(self.as_bytes())
    }
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
