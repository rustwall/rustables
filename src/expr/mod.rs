//! A module with all the nftables expressions that can be added to [`Rule`]s to build up how
//! they match against packets.
//!
//! [`Rule`]: struct.Rule.html

use std::borrow::Cow;
use std::fmt::Debug;
use std::mem::transmute;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::slice::Iter;

use super::rule::Rule;
use crate::create_wrapper_type;
use crate::nlmsg::AttributeDecoder;
use crate::nlmsg::NfNetlinkAttribute;
use crate::nlmsg::NfNetlinkDeserializable;
use crate::parser::pad_netlink_object;
use crate::parser::pad_netlink_object_with_variable_size;
use crate::parser::write_attribute;
use crate::parser::DecodeError;
use crate::parser::InnerFormat;
use crate::sys::{self, nlattr};
use libc::NLA_TYPE_MASK;
use thiserror::Error;

mod bitwise;
pub use self::bitwise::*;

/*
mod cmp;
pub use self::cmp::*;

mod counter;
pub use self::counter::*;

pub mod ct;
pub use self::ct::*;
*/

mod immediate;
pub use self::immediate::*;

mod log;
pub use self::log::*;
/*

mod lookup;
pub use self::lookup::*;

mod masquerade;
pub use self::masquerade::*;
*/

mod meta;
pub use self::meta::*;

/*
mod nat;
pub use self::nat::*;

mod payload;
pub use self::payload::*;

mod reject;
pub use self::reject::{IcmpCode, Reject};
*/

mod register;
pub use self::register::Register;

mod verdict;
pub use self::verdict::*;

/*

mod wrapper;
pub use self::wrapper::ExpressionWrapper;
*/

#[derive(Debug, Error)]
pub enum ExpressionError {
    #[error("The log prefix string is more than 127 characters long")]
    /// The log prefix string is more than 127 characters long
    TooLongLogPrefix,

    #[error("The expected expression type doesn't match the name of the raw expression")]
    /// The expected expression type doesn't match the name of the raw expression.
    InvalidExpressionKind,

    #[error("Deserializing the requested type isn't implemented yet")]
    /// Deserializing the requested type isn't implemented yet.
    NotImplemented,

    #[error("The expression value cannot be deserialized to the requested type")]
    /// The expression value cannot be deserialized to the requested type.
    InvalidValue,

    #[error("A pointer was null while a non-null pointer was expected")]
    /// A pointer was null while a non-null pointer was expected.
    NullPointer,

    #[error(
        "The size of a raw value was incoherent with the expected type of the deserialized value"
    )]
    /// The size of a raw value was incoherent with the expected type of the deserialized value/
    InvalidDataSize,
}

pub trait Expression {
    fn get_name() -> &'static str;
}

create_wrapper_type!(
    nested without_deser : RawExpression, [
    // Define the action netfilter will apply to packets processed by this chain, but that did not match any rules in it.
    (
        get_name,
        set_name,
        with_name,
        sys::NFTA_EXPR_NAME,
        name,
        String
    ),
    (
        get_data,
        set_data,
        with_data,
        sys::NFTA_EXPR_DATA,
        data,
        ExpressionVariant
    )
]);

impl RawExpression {
    pub fn new<T>(expr: T) -> Self
    where
        T: Expression,
        ExpressionVariant: From<T>,
    {
        RawExpression::default()
            .with_name(T::get_name())
            .with_data(ExpressionVariant::from(expr))
    }
}

#[macro_export]
macro_rules! create_expr_variant {
    ($enum:ident $(, [$name:ident, $type:ty])+) => {
        #[derive(Debug, Clone, PartialEq, Eq)]
        pub enum $enum {
            $(
                $name($type),
            )+
        }

        impl $crate::nlmsg::NfNetlinkAttribute for $enum {
            fn is_nested(&self) -> bool {
                true
            }

            fn get_size(&self) -> usize {
                match self {
                    $(
                        $enum::$name(val) => val.get_size(),
                    )+
                }
            }

            unsafe fn write_payload(&self, addr: *mut u8) {
                match self {
                    $(
                        $enum::$name(val) => val.write_payload(addr),
                    )+
                }
            }
        }

        $(
            impl From<$type> for $enum {
                fn from(val: $type) -> Self {
                    $enum::$name(val)
                }
            }
        )+

        impl $crate::nlmsg::AttributeDecoder for RawExpression {
            fn decode_attribute(
                &mut self,
                attr_type: u16,
                buf: &[u8],
            ) -> Result<(), $crate::parser::DecodeError> {
                debug!("Decoding attribute {} in an expression", attr_type);
                match attr_type {
                    x if x == sys::NFTA_EXPR_NAME => {
                        debug!("Calling {}::deserialize()", std::any::type_name::<String>());
                        let (val, remaining) = String::deserialize(buf)?;
                        if remaining.len() != 0 {
                            return Err($crate::parser::DecodeError::InvalidDataSize);
                        }
                        self.name = Some(val);
                        Ok(())
                    },
                    x if x == sys::NFTA_EXPR_DATA => {
                        // we can assume we have already the name parsed, as that's how we identify the
                        // type of expression
                        let name = self.name.as_ref()
                            .ok_or($crate::parser::DecodeError::MissingExpressionName)?;
                        match name {
                            $(
                                x if x == <$type>::get_name() => {
                                    debug!("Calling {}::deserialize()", std::any::type_name::<$type>());
                                    let (res, remaining) =  <$type>::deserialize(buf)?;
                                    if remaining.len() != 0 {
                                            return Err($crate::parser::DecodeError::InvalidDataSize);
                                    }
                                    self.data = Some(ExpressionVariant::from(res));
                                    Ok(())
                                },
                            )+
                            name => {
                                info!("Unrecognized expression '{}', generating an ExpressionRaw", name);
                                self.data = Some(ExpressionVariant::ExpressionRaw(ExpressionRaw::deserialize(buf)?.0));
                                Ok(())
                            }
                        }
                    },
                    _ => Err(DecodeError::UnsupportedAttributeType(attr_type)),
                }
            }
        }
    };
}

create_expr_variant!(
    ExpressionVariant,
    [Log, Log],
    [Immediate, Immediate],
    [Bitwise, Bitwise],
    [ExpressionRaw, ExpressionRaw],
    [Meta, Meta]
);

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ExpressionList {
    exprs: Vec<RawExpression>,
}

impl ExpressionList {
    pub fn builder() -> Self {
        Self { exprs: Vec::new() }
    }

    /// Useful to add raw expressions because RawExpression cannot infer alone its type
    pub fn add_raw_expression(&mut self, e: RawExpression) {
        self.exprs.push(e);
    }

    pub fn add_expression<T>(&mut self, e: T)
    where
        T: Expression,
        ExpressionVariant: From<T>,
    {
        self.exprs.push(RawExpression::new(e));
    }

    pub fn with_expression<T>(mut self, e: T) -> Self
    where
        T: Expression,
        ExpressionVariant: From<T>,
    {
        self.add_expression(e);
        self
    }

    pub fn iter<'a>(&'a self) -> impl Iterator<Item = &'a ExpressionVariant> {
        self.exprs.iter().map(|e| e.get_data().unwrap())
    }
}

impl NfNetlinkAttribute for ExpressionList {
    fn is_nested(&self) -> bool {
        true
    }

    fn get_size(&self) -> usize {
        // one nlattr LIST_ELEM per object
        self.exprs.iter().fold(0, |acc, item| {
            acc + item.get_size() + pad_netlink_object::<nlattr>()
        })
    }

    unsafe fn write_payload(&self, mut addr: *mut u8) {
        for item in &self.exprs {
            write_attribute(sys::NFTA_LIST_ELEM, item, addr);
            addr = addr.offset((pad_netlink_object::<nlattr>() + item.get_size()) as isize);
        }
    }
}

impl NfNetlinkDeserializable for ExpressionList {
    fn deserialize(buf: &[u8]) -> Result<(Self, &[u8]), DecodeError> {
        let mut exprs = Vec::new();

        let mut pos = 0;
        while buf.len() - pos > pad_netlink_object::<nlattr>() {
            let nlattr = unsafe { *transmute::<*const u8, *const nlattr>(buf[pos..].as_ptr()) };
            // ignore the byteorder and nested attributes
            let nla_type = nlattr.nla_type & NLA_TYPE_MASK as u16;

            if nla_type != sys::NFTA_LIST_ELEM {
                return Err(DecodeError::UnsupportedAttributeType(nla_type));
            }

            let (expr, remaining) = RawExpression::deserialize(
                &buf[pos + pad_netlink_object::<nlattr>()..pos + nlattr.nla_len as usize],
            )?;
            if remaining.len() != 0 {
                return Err(DecodeError::InvalidDataSize);
            }
            exprs.push(expr);

            pos += pad_netlink_object_with_variable_size(nlattr.nla_len as usize);
        }

        if pos != buf.len() {
            Err(DecodeError::InvalidDataSize)
        } else {
            Ok((Self { exprs }, &[]))
        }
    }
}

impl<T> From<Vec<T>> for ExpressionList
where
    ExpressionVariant: From<T>,
    T: Expression,
{
    fn from(v: Vec<T>) -> Self {
        ExpressionList {
            exprs: v.into_iter().map(RawExpression::new).collect(),
        }
    }
}

create_wrapper_type!(
  nested : ExpressionData,
    [
        (
            get_value,
            set_value,
            with_value,
            sys::NFTA_DATA_VALUE,
            value,
            Vec<u8>
        ),
        (
            get_verdict,
            set_verdict,
            with_verdict,
            sys::NFTA_DATA_VERDICT,
            verdict,
            VerdictAttribute
        )
    ]
);

// default type for expressions that we do not handle yet
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpressionRaw(Vec<u8>);

impl NfNetlinkAttribute for ExpressionRaw {
    fn get_size(&self) -> usize {
        self.0.get_size()
    }

    unsafe fn write_payload(&self, addr: *mut u8) {
        self.0.write_payload(addr);
    }
}

impl NfNetlinkDeserializable for ExpressionRaw {
    fn deserialize(buf: &[u8]) -> Result<(Self, &[u8]), DecodeError> {
        Ok((ExpressionRaw(buf.to_vec()), &[]))
    }
}

// Because we loose the name of the expression when parsing, this is the only expression
// where deserializing a message and then reserializing it is invalid
impl Expression for ExpressionRaw {
    fn get_name() -> &'static str {
        "unknown_expression"
    }
}
