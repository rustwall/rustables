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
use crate::nlmsg::AttributeDecoder;
use crate::nlmsg::NfNetlinkAttribute;
use crate::nlmsg::NfNetlinkAttributes;
use crate::nlmsg::NfNetlinkDeserializable;
use crate::parser::pad_netlink_object;
use crate::parser::pad_netlink_object_with_variable_size;
use crate::parser::write_attribute;
use crate::parser::AttributeType;
use crate::parser::DecodeError;
use crate::parser::InnerFormat;
use crate::sys::{self, nlattr};
use libc::NLA_TYPE_MASK;
use thiserror::Error;

/*
mod bitwise;
pub use self::bitwise::*;

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

mod meta;
pub use self::meta::*;

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

// wrapper for the general case, as we need to create many holder types given the depth of some
// netlink expressions
#[macro_export]
macro_rules! create_expr_type {
    (without_decoder : $struct:ident, [$(($getter_name:ident, $setter_name:ident, $in_place_edit_name:ident, $attr_name:expr, $internal_name:ident, $type:ty)),+]) => {
        #[derive(Clone, PartialEq, Eq)]
        pub struct $struct {
            inner: $crate::nlmsg::NfNetlinkAttributes,
        }


        $crate::impl_attr_getters_and_setters!(without_decoder $struct, [$(($getter_name, $setter_name, $in_place_edit_name, $attr_name, $internal_name, $type)),+]);

        impl std::fmt::Debug for $struct {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                use $crate::parser::InnerFormat;
                self.inner_format_struct(f.debug_struct(stringify!($struct)))?
                    .finish()
            }
        }


        impl $crate::nlmsg::NfNetlinkDeserializable for $struct {
            fn deserialize(buf: &[u8]) -> Result<(Self, &[u8]), $crate::parser::DecodeError> {
                let reader = $crate::parser::NfNetlinkAttributeReader::new(buf, buf.len())?;
                let inner = reader.decode::<Self>()?;
                Ok(($struct { inner }, &[]))
            }
        }

    };
    ($struct:ident, [$(($getter_name:ident, $setter_name:ident, $in_place_edit_name:ident, $attr_name:expr, $internal_name:ident, $type:ty)),+]) => {
        create_expr_type!(without_decoder : $struct, [$(($getter_name, $setter_name, $in_place_edit_name, $attr_name, $internal_name, $type)),+]);
        $crate::impl_attr_getters_and_setters!(decoder $struct, [$(($getter_name, $setter_name, $in_place_edit_name, $attr_name, $internal_name, $type)),+]);
    };
    (with_builder : $struct:ident, [$(($getter_name:ident, $setter_name:ident, $in_place_edit_name:ident, $attr_name:expr, $internal_name:ident, $type:ty)),+]) => {
        create_expr_type!($struct, [$(($getter_name, $setter_name, $in_place_edit_name, $attr_name, $internal_name, $type)),+]);

        impl $struct {
            pub fn builder() -> Self {
                Self { inner: $crate::nlmsg::NfNetlinkAttributes::new() }
            }
        }
    };
    (inline $($($attrs:ident) +)? :  $struct:ident, [$(($getter_name:ident, $setter_name:ident, $in_place_edit_name:ident, $attr_name:expr, $internal_name:ident, $type:ty)),+]) => {
        create_expr_type!($($($attrs) + :)? $struct, [$(($getter_name, $setter_name, $in_place_edit_name, $attr_name, $internal_name, $type)),+]);

        impl $crate::nlmsg::NfNetlinkAttribute for $struct {
            fn get_size(&self) -> usize {
                self.inner.get_size()
            }

            unsafe fn write_payload(&self, addr: *mut u8) {
                self.inner.write_payload(addr)
            }
        }
    };
    (nested $($($attrs:ident) +)? : $struct:ident, [$(($getter_name:ident, $setter_name:ident, $in_place_edit_name:ident, $attr_name:expr, $internal_name:ident, $type:ty)),+]) => {
        create_expr_type!($($($attrs) + :)? $struct, [$(($getter_name, $setter_name, $in_place_edit_name, $attr_name, $internal_name, $type)),+]);

        impl $crate::nlmsg::NfNetlinkAttribute for $struct {
            fn is_nested(&self) -> bool {
                true
            }

            fn get_size(&self) -> usize {
                self.inner.get_size()
            }

            unsafe fn write_payload(&self, addr: *mut u8) {
                self.inner.write_payload(addr)
            }
        }
    };
}

create_expr_type!(
    nested without_decoder : ExpressionHolder, [
    // Define the action netfilter will apply to packets processed by this chain, but that did not match any rules in it.
    (
        get_name,
        set_name,
        with_name,
        sys::NFTA_EXPR_NAME,
        String,
        String
    ),
    (
        get_data,
        set_data,
        with_data,
        sys::NFTA_EXPR_DATA,
        ExpressionVariant,
        ExpressionVariant
    )
]);

impl ExpressionHolder {
    pub fn new<T>(expr: T) -> Self
    where
        T: Expression,
        ExpressionVariant: From<T>,
    {
        ExpressionHolder {
            inner: NfNetlinkAttributes::new(),
        }
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

        impl AttributeDecoder for ExpressionHolder {
            fn decode_attribute(
                attrs: &NfNetlinkAttributes,
                attr_type: u16,
                buf: &[u8],
            ) -> Result<AttributeType, DecodeError> {
                debug!("Decoding attribute {} in an expression", attr_type);
                match attr_type {
                    x if x == sys::NFTA_EXPR_NAME => {
                        debug!("Calling {}::deserialize()", std::any::type_name::<String>());
                        let (val, remaining) = String::deserialize(buf)?;
                        if remaining.len() != 0 {
                            return Err(DecodeError::InvalidDataSize);
                        }
                        Ok(AttributeType::String(val))
                    },
                    x if x == sys::NFTA_EXPR_DATA => {
                        // we can assume we have already the name parsed, as that's how we identify the
                        // type of expression
                        let name = attrs
                            .get_attr(sys::NFTA_EXPR_NAME)
                            .ok_or(DecodeError::MissingExpressionName)?;
                        match name {
                            $(
                                AttributeType::String(x) if x == <$type>::get_name() => {
                                    debug!("Calling {}::deserialize()", std::any::type_name::<$type>());
                                    let (res, remaining) =  <$type>::deserialize(buf)?;
                                    if remaining.len() != 0 {
                                            return Err($crate::parser::DecodeError::InvalidDataSize);
                                    }
                                    Ok(AttributeType::ExpressionVariant(ExpressionVariant::from(res)))
                                },
                            )+
                            AttributeType::String(name) => Err(DecodeError::UnknownExpressionName(name.to_string())),
                            _ => unreachable!()
                        }
                    },
                    _ => Err(DecodeError::UnsupportedAttributeType(attr_type)),
                }
            }
        }
    };
}

create_expr_variant!(ExpressionVariant, [Log, Log], [Immediate, Immediate]);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpressionList {
    exprs: Vec<AttributeType>,
}

impl ExpressionList {
    pub fn builder() -> Self {
        Self { exprs: Vec::new() }
    }

    pub fn add_expression<T>(&mut self, e: T)
    where
        T: Expression,
        ExpressionVariant: From<T>,
    {
        self.exprs
            .push(AttributeType::Expression(ExpressionHolder::new(e)));
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
        self.exprs.iter().map(|t| match t {
            AttributeType::Expression(e) => e.get_data().unwrap(),
            _ => unreachable!(),
        })
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

            let (expr, remaining) = ExpressionHolder::deserialize(
                &buf[pos + pad_netlink_object::<nlattr>()..pos + nlattr.nla_len as usize],
            )?;
            if remaining.len() != 0 {
                return Err(DecodeError::InvalidDataSize);
            }
            exprs.push(AttributeType::Expression(expr));

            pos += pad_netlink_object_with_variable_size(nlattr.nla_len as usize);
        }

        if pos != buf.len() {
            Err(DecodeError::InvalidDataSize)
        } else {
            Ok((Self { exprs }, &[]))
        }
    }
}

#[macro_export(local_inner_macros)]
macro_rules! nft_expr {
    (bitwise mask $mask:expr,xor $xor:expr) => {
        nft_expr_bitwise!(mask $mask, xor $xor)
    };
    (cmp $op:tt $data:expr) => {
        nft_expr_cmp!($op $data)
    };
    (counter) => {
        $crate::expr::Counter { nb_bytes: 0, nb_packets: 0}
    };
    (ct $key:ident set) => {
        nft_expr_ct!($key set)
    };
    (ct $key:ident) => {
        nft_expr_ct!($key)
    };
    (immediate $expr:ident $value:expr) => {
        nft_expr_immediate!($expr $value)
    };
    (log group $group:ident prefix $prefix:expr) => {
        nft_expr_log!(group $group prefix $prefix)
    };
    (log group $group:ident) => {
        nft_expr_log!(group $group)
    };
    (log prefix $prefix:expr) => {
        nft_expr_log!(prefix $prefix)
    };
    (log) => {
        nft_expr_log!()
    };
    (lookup $set:expr) => {
        nft_expr_lookup!($set)
    };
    (masquerade) => {
        $crate::expr::Masquerade
    };
    (meta $expr:ident set) => {
        nft_expr_meta!($expr set)
    };
    (meta $expr:ident) => {
        nft_expr_meta!($expr)
    };
    (payload $proto:ident $field:ident) => {
        nft_expr_payload!($proto $field)
    };
    (verdict $verdict:ident) => {
        nft_expr_verdict!($verdict)
    };
    (verdict $verdict:ident $chain:expr) => {
        nft_expr_verdict!($verdict $chain)
    };
}
