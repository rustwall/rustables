use std::{
    any::TypeId,
    convert::TryFrom,
    fmt::{Debug, DebugStruct},
    mem::{size_of, transmute},
    string::FromUtf8Error,
};

use thiserror::Error;

use crate::{
    expr::ExpressionHolder,
    nlmsg::{
        AttributeDecoder, NetlinkType, NfNetlinkAttribute, NfNetlinkAttributes,
        NfNetlinkDeserializable, NfNetlinkWriter,
    },
    sys::{
        nfgenmsg, nlattr, nlmsgerr, nlmsghdr, NFNETLINK_V0, NFNL_MSG_BATCH_BEGIN,
        NFNL_MSG_BATCH_END, NFNL_SUBSYS_NFTABLES, NLA_F_NESTED, NLA_TYPE_MASK, NLMSG_ALIGNTO,
        NLMSG_DONE, NLMSG_ERROR, NLMSG_MIN_TYPE, NLMSG_NOOP, NLM_F_DUMP_INTR,
    },
    ProtocolFamily,
};

#[derive(Error, Debug)]
pub enum DecodeError {
    #[error("The buffer is too small to hold a valid message")]
    BufTooSmall,

    #[error("The message is too small")]
    NlMsgTooSmall,

    #[error("The message holds unexpected data")]
    InvalidDataSize,

    #[error("Missing information in the chain to create a rule")]
    MissingChainInformationError,

    #[error("The length of the arguments are not compatible with each other")]
    IncompatibleLength,

    #[error("Invalid subsystem, expected NFTABLES")]
    InvalidSubsystem(u8),

    #[error("Invalid version, expected NFNETLINK_V0")]
    InvalidVersion(u8),

    #[error("Invalid port ID")]
    InvalidPortId(u32),

    #[error("Invalid sequence number")]
    InvalidSeq(u32),

    #[error("The generation number was bumped in the kernel while the operation was running, interrupting it")]
    ConcurrentGenerationUpdate,

    #[error("Unsupported message type")]
    UnsupportedType(u16),

    #[error("Invalid attribute type")]
    InvalidAttributeType,

    #[error("Invalid type for a chain")]
    UnknownChainType,

    #[error("Invalid policy for a chain")]
    UnknownChainPolicy,

    #[error("Invalid value for a register")]
    UnknownRegisterValue,

    #[error("Invalid type for a verdict expression")]
    UnknownExpressionVerdictType,

    #[error("The object does not contain a name for the expression being parsed")]
    MissingExpressionName,

    #[error("Unsupported attribute type")]
    UnsupportedAttributeType(u16),

    #[error("Unexpected message type")]
    UnexpectedType(u16),

    #[error("The decoded String is not UTF8 compliant")]
    StringDecodeFailure(#[from] FromUtf8Error),

    #[error("Invalid value for a protocol family")]
    InvalidProtocolFamily(i32),

    #[error("A custom error occured")]
    Custom(Box<dyn std::error::Error + 'static>),
}

/// The largest nf_tables netlink message is the set element message, which contains the
/// NFTA_SET_ELEM_LIST_ELEMENTS attribute. This attribute is a nest that describes the set
/// elements. Given that the netlink attribute length (nla_len) is 16 bits, the largest message is
/// a bit larger than 64 KBytes.
pub fn nft_nlmsg_maxsize() -> u32 {
    u32::from(::std::u16::MAX) + unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as u32
}

#[inline]
pub const fn pad_netlink_object_with_variable_size(size: usize) -> usize {
    // align on a 4 bytes boundary
    (size + (NLMSG_ALIGNTO as usize - 1)) & !(NLMSG_ALIGNTO as usize - 1)
}

#[inline]
pub const fn pad_netlink_object<T>() -> usize {
    let size = size_of::<T>();
    pad_netlink_object_with_variable_size(size)
}

pub fn get_subsystem_from_nlmsghdr_type(x: u16) -> u8 {
    ((x & 0xff00) >> 8) as u8
}

pub fn get_operation_from_nlmsghdr_type(x: u16) -> u8 {
    (x & 0x00ff) as u8
}

pub fn get_nlmsghdr(buf: &[u8]) -> Result<nlmsghdr, DecodeError> {
    let size_of_hdr = size_of::<nlmsghdr>();

    if buf.len() < size_of_hdr {
        return Err(DecodeError::BufTooSmall);
    }

    let nlmsghdr_ptr = buf[0..size_of_hdr].as_ptr() as *const nlmsghdr;
    let nlmsghdr = unsafe { *nlmsghdr_ptr };

    if nlmsghdr.nlmsg_len as usize > buf.len() || (nlmsghdr.nlmsg_len as usize) < size_of_hdr {
        return Err(DecodeError::NlMsgTooSmall);
    }

    if nlmsghdr.nlmsg_flags & NLM_F_DUMP_INTR as u16 != 0 {
        return Err(DecodeError::ConcurrentGenerationUpdate);
    }

    Ok(nlmsghdr)
}

#[derive(Debug, Clone, PartialEq)]
pub enum NlMsg<'a> {
    Done,
    Noop,
    Error(nlmsgerr),
    NfGenMsg(nfgenmsg, &'a [u8]),
}

pub fn parse_nlmsg<'a>(buf: &'a [u8]) -> Result<(nlmsghdr, NlMsg<'a>), DecodeError> {
    // in theory the message is composed of the following parts:
    // - nlmsghdr (contains the message size and type)
    // - struct nlmsgerr OR nfgenmsg (nftables header that describes the message family)
    // - the raw value that we want to validate (if the previous part is nfgenmsg)
    let hdr = get_nlmsghdr(buf)?;

    let size_of_hdr = pad_netlink_object::<nlmsghdr>();

    if hdr.nlmsg_type < NLMSG_MIN_TYPE as u16 {
        match hdr.nlmsg_type as u32 {
            x if x == NLMSG_NOOP => return Ok((hdr, NlMsg::Noop)),
            x if x == NLMSG_ERROR => {
                if (hdr.nlmsg_len as usize) < size_of_hdr + size_of::<nlmsgerr>() {
                    return Err(DecodeError::NlMsgTooSmall);
                }
                let mut err = unsafe {
                    *(buf[size_of_hdr..size_of_hdr + size_of::<nlmsgerr>()].as_ptr()
                        as *const nlmsgerr)
                };
                // some APIs return negative values, while other return positive values
                err.error = err.error.abs();
                return Ok((hdr, NlMsg::Error(err)));
            }
            x if x == NLMSG_DONE => return Ok((hdr, NlMsg::Done)),
            x => return Err(DecodeError::UnsupportedType(x as u16)),
        }
    }

    // batch messages are not specific to the nftables subsystem
    if hdr.nlmsg_type != NFNL_MSG_BATCH_BEGIN as u16 && hdr.nlmsg_type != NFNL_MSG_BATCH_END as u16
    {
        // verify that we are decoding nftables messages
        let subsys = get_subsystem_from_nlmsghdr_type(hdr.nlmsg_type);
        if subsys != NFNL_SUBSYS_NFTABLES as u8 {
            return Err(DecodeError::InvalidSubsystem(subsys));
        }
    }

    let size_of_nfgenmsg = pad_netlink_object::<nfgenmsg>();
    if hdr.nlmsg_len as usize > buf.len()
        || (hdr.nlmsg_len as usize) < size_of_hdr + size_of_nfgenmsg
    {
        return Err(DecodeError::NlMsgTooSmall);
    }

    let nfgenmsg_ptr = buf[size_of_hdr..size_of_hdr + size_of_nfgenmsg].as_ptr() as *const nfgenmsg;
    let nfgenmsg = unsafe { *nfgenmsg_ptr };

    if nfgenmsg.version != NFNETLINK_V0 as u8 {
        return Err(DecodeError::InvalidVersion(nfgenmsg.version));
    }

    let raw_value = &buf[size_of_hdr + size_of_nfgenmsg..hdr.nlmsg_len as usize];

    Ok((hdr, NlMsg::NfGenMsg(nfgenmsg, raw_value)))
}

/// Write the attribute, preceded by a `libc::nlattr`
// rewrite of `mnl_attr_put`
pub unsafe fn write_attribute<'a>(ty: NetlinkType, obj: &AttributeType, mut buf: *mut u8) {
    let header_len = pad_netlink_object::<libc::nlattr>();
    // copy the header
    *(buf as *mut nlattr) = nlattr {
        // nla_len contains the header size + the unpadded attribute length
        nla_len: (header_len + obj.get_size() as usize) as u16,
        nla_type: if obj.is_nested() {
            ty | NLA_F_NESTED as u16
        } else {
            ty
        },
    };
    buf = buf.offset(pad_netlink_object::<nlattr>() as isize);
    // copy the attribute data itself
    obj.write_payload(buf);
}

impl NfNetlinkAttribute for u8 {
    unsafe fn write_payload(&self, addr: *mut u8) {
        *addr = *self;
    }
}

impl NfNetlinkDeserializable for u8 {
    fn deserialize(buf: &[u8]) -> Result<(Self, &[u8]), DecodeError> {
        Ok((buf[0], &buf[1..]))
    }
}

impl NfNetlinkAttribute for u16 {
    unsafe fn write_payload(&self, addr: *mut u8) {
        *(addr as *mut Self) = self.to_be();
    }
}

impl NfNetlinkDeserializable for u16 {
    fn deserialize(buf: &[u8]) -> Result<(Self, &[u8]), DecodeError> {
        Ok((u16::from_be_bytes([buf[0], buf[1]]), &buf[2..]))
    }
}

impl NfNetlinkAttribute for i32 {
    unsafe fn write_payload(&self, addr: *mut u8) {
        *(addr as *mut Self) = self.to_be();
    }
}

impl NfNetlinkDeserializable for i32 {
    fn deserialize(buf: &[u8]) -> Result<(Self, &[u8]), DecodeError> {
        Ok((
            i32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]),
            &buf[4..],
        ))
    }
}

impl NfNetlinkAttribute for u32 {
    unsafe fn write_payload(&self, addr: *mut u8) {
        *(addr as *mut Self) = self.to_be();
    }
}

impl NfNetlinkDeserializable for u32 {
    fn deserialize(buf: &[u8]) -> Result<(Self, &[u8]), DecodeError> {
        Ok((
            u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]),
            &buf[4..],
        ))
    }
}

impl NfNetlinkAttribute for u64 {
    unsafe fn write_payload(&self, addr: *mut u8) {
        *(addr as *mut Self) = self.to_be();
    }
}

impl NfNetlinkDeserializable for u64 {
    fn deserialize(buf: &[u8]) -> Result<(Self, &[u8]), DecodeError> {
        Ok((
            u64::from_be_bytes([
                buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7],
            ]),
            &buf[8..],
        ))
    }
}

// TODO: safe handling for null-delimited strings
impl NfNetlinkAttribute for String {
    fn get_size(&self) -> usize {
        self.len()
    }

    unsafe fn write_payload(&self, addr: *mut u8) {
        std::ptr::copy_nonoverlapping(self.as_bytes().as_ptr(), addr, self.len());
    }
}

impl NfNetlinkDeserializable for String {
    fn deserialize(mut buf: &[u8]) -> Result<(Self, &[u8]), DecodeError> {
        // ignore the NULL byte terminator, if any
        if buf.len() > 0 && buf[buf.len() - 1] == 0 {
            buf = &buf[..buf.len() - 1];
        }
        Ok((String::from_utf8(buf.to_vec())?, &[]))
    }
}

impl NfNetlinkAttribute for Vec<u8> {
    fn get_size(&self) -> usize {
        self.len()
    }

    unsafe fn write_payload(&self, addr: *mut u8) {
        std::ptr::copy_nonoverlapping(self.as_ptr(), addr, self.len());
    }
}

impl NfNetlinkDeserializable for Vec<u8> {
    fn deserialize(buf: &[u8]) -> Result<(Self, &[u8]), DecodeError> {
        Ok((buf.to_vec(), &[]))
    }
}

impl NfNetlinkAttribute for ProtocolFamily {
    unsafe fn write_payload(&self, addr: *mut u8) {
        (*self as i32).write_payload(addr);
    }
}

impl NfNetlinkDeserializable for ProtocolFamily {
    fn deserialize(buf: &[u8]) -> Result<(Self, &[u8]), DecodeError> {
        let (v, remaining_data) = i32::deserialize(buf)?;
        Ok((Self::try_from(v)?, remaining_data))
    }
}

pub struct NfNetlinkAttributeReader<'a> {
    buf: &'a [u8],
    pos: usize,
    remaining_size: usize,
    attrs: NfNetlinkAttributes,
}

impl<'a> NfNetlinkAttributeReader<'a> {
    pub fn new(buf: &'a [u8], remaining_size: usize) -> Result<Self, DecodeError> {
        if buf.len() < remaining_size {
            return Err(DecodeError::BufTooSmall);
        }

        Ok(Self {
            buf,
            pos: 0,
            remaining_size,
            attrs: NfNetlinkAttributes::new(),
        })
    }

    pub fn get_raw_data(&self) -> &'a [u8] {
        &self.buf[self.pos..]
    }

    pub fn decode<T: AttributeDecoder + 'static>(
        mut self,
    ) -> Result<NfNetlinkAttributes, DecodeError> {
        debug!(
            "Calling NfNetlinkAttributeReader::decode() on {}",
            std::any::type_name::<T>()
        );
        while self.remaining_size > pad_netlink_object::<nlattr>() {
            let nlattr =
                unsafe { *transmute::<*const u8, *const nlattr>(self.buf[self.pos..].as_ptr()) };
            // ignore the byteorder and nested attributes
            let nla_type = nlattr.nla_type & NLA_TYPE_MASK as u16;

            self.pos += pad_netlink_object::<nlattr>();
            let attr_remaining_size = nlattr.nla_len as usize - pad_netlink_object::<nlattr>();
            match T::decode_attribute(
                &self.attrs,
                nla_type,
                &self.buf[self.pos..self.pos + attr_remaining_size],
            ) {
                Ok(x) => self.attrs.set_attr(nla_type, x),
                Err(DecodeError::UnsupportedAttributeType(t)) => info!(
                    "Ignoring unsupported attribute type {} for type {}",
                    t,
                    std::any::type_name::<T>()
                ),
                Err(e) => return Err(e),
            }
            self.pos += pad_netlink_object_with_variable_size(attr_remaining_size);

            self.remaining_size -= pad_netlink_object_with_variable_size(nlattr.nla_len as usize);
        }

        if self.remaining_size != 0 {
            Err(DecodeError::InvalidDataSize)
        } else {
            Ok(self.attrs)
        }
    }
}

#[macro_export]
macro_rules! impl_attribute_holder {
    ($enum_name:ident, $([$internal_name:ident, $type:ty]),+) => {
        #[derive(Debug, Clone, PartialEq, Eq)]
        pub enum $enum_name {
            $(
                $internal_name($type),
            )+
        }

        impl NfNetlinkAttribute for $enum_name {
            fn is_nested(&self) -> bool {
                match self {
                    $(
                        $enum_name::$internal_name(val) => val.is_nested()
                    ),+
                }
            }

            fn get_size(&self) -> usize {
                 match self {
                    $(
                        $enum_name::$internal_name(val) => val.get_size()
                    ),+
                 }
            }

            unsafe fn write_payload(&self, addr: *mut u8) {
                match self {
                    $(
                        $enum_name::$internal_name(val) => val.write_payload(addr)
                    ),+
                 }
            }
        }

        impl $enum_name {
            $(
                #[allow(non_snake_case)]
                pub fn $internal_name(&self) -> Option<&$type> {
                    match self {
                        $enum_name::$internal_name(val) => Some(val),
                        _ => None
                    }
                }
            )+
        }
    };
}

pub trait InnerFormat {
    fn inner_format_struct<'a, 'b: 'a>(
        &'a self,
        s: DebugStruct<'a, 'b>,
    ) -> Result<DebugStruct<'a, 'b>, std::fmt::Error>;
}

impl_attribute_holder!(
    AttributeType,
    [String, String],
    [U8, u8],
    [U16, u16],
    [I32, i32],
    [U32, u32],
    [U64, u64],
    [VecU8, Vec<u8>],
    [ChainHook, crate::chain::Hook],
    [ChainPolicy, crate::chain::ChainPolicy],
    [ChainType, crate::chain::ChainType],
    [ProtocolFamily, crate::ProtocolFamily],
    [Expression, crate::expr::ExpressionHolder],
    [ExpressionVariant, crate::expr::ExpressionVariant],
    [ExpressionList, crate::expr::ExpressionList],
    [ExprLog, crate::expr::Log],
    [ExprImmediate, crate::expr::Immediate],
    [ExprData, crate::expr::ExpressionData],
    [ExprVerdictAttribute, crate::expr::VerdictAttribute],
    [ExprVerdictType, crate::expr::VerdictType],
    [Register, crate::expr::Register],
    [ExprRaw, crate::expr::ExpressionRaw]
);

#[macro_export]
macro_rules! impl_attr_getters_and_setters {
    (without_decoder $struct:ident, [$(($getter_name:ident, $setter_name:ident, $in_place_edit_name:ident, $attr_name:expr, $internal_name:ident, $type:ty)),+]) => {
        impl $struct {
            $(
                #[allow(dead_code)]
                pub fn $getter_name(&self) -> Option<&$type> {
                    self.inner.get_attr($attr_name as $crate::nlmsg::NetlinkType).map(|x| x.$internal_name()).flatten()
                }

                #[allow(dead_code)]
                pub fn $setter_name(&mut self, val: impl Into<$type>) {
                    self.inner.set_attr($attr_name as $crate::nlmsg::NetlinkType, $crate::parser::AttributeType::$internal_name(val.into()));
                }

                #[allow(dead_code)]
                pub fn $in_place_edit_name(mut self, val: impl Into<$type>) -> Self {
                    self.inner.set_attr($attr_name as $crate::nlmsg::NetlinkType, $crate::parser::AttributeType::$internal_name(val.into()));
                    self
                }

            )+
        }

        impl $crate::parser::InnerFormat for $struct {
            fn inner_format_struct<'a, 'b: 'a>(&'a self, mut s: std::fmt::DebugStruct<'a, 'b>) -> Result<std::fmt::DebugStruct<'a, 'b>, std::fmt::Error> {
                $(
                    // Rewrite attributes names to be readable: 'sys::NFTA_CHAIN_NAME' -> 'name'
                    // Performance must be terrible, but this is the Debug impl anyway, so that
                    // must mean we can afford to be slow, right? ;)
                    if let Some(val) = self.$getter_name() {
                        let mut attr = stringify!($attr_name);
                        if let Some((nfta_idx, _match )) = attr.rmatch_indices("NFTA_").next() {
                            if let Some(underscore_idx) = &attr[nfta_idx+5..].find('_') {
                                attr = &attr[nfta_idx+underscore_idx+6..];
                            }
                        }
                        let attr = attr.to_lowercase();
                        s.field(&attr, val);
                    }
                )+
                Ok(s)
            }
        }

    };
    (decoder $struct:ident, [$(($getter_name:ident, $setter_name:ident, $in_place_edit_name:ident, $attr_name:expr, $internal_name:ident, $type:ty)),+]) => {
        impl $crate::nlmsg::AttributeDecoder for $struct {
            #[allow(dead_code)]
            fn decode_attribute(_attrs: &$crate::nlmsg::NfNetlinkAttributes, attr_type: u16, buf: &[u8]) -> Result<$crate::parser::AttributeType, $crate::parser::DecodeError> {
                use $crate::nlmsg::NfNetlinkDeserializable;
                debug!("Decoding attribute {} in type {}", attr_type, std::any::type_name::<$struct>());
                match attr_type {
                    $(
                        x if x == $attr_name => {
                            debug!("Calling {}::deserialize()", std::any::type_name::<$type>());
                            let (val, remaining) = <$type>::deserialize(buf)?;
                            if remaining.len() != 0 {
                                return Err($crate::parser::DecodeError::InvalidDataSize);
                            }
                            Ok($crate::parser::AttributeType::$internal_name(val))
                        },
                    )+
                    _ => Err($crate::parser::DecodeError::UnsupportedAttributeType(attr_type)),
                }
            }
        }
    };
    ($struct:ident, [$(($getter_name:ident, $setter_name:ident, $in_place_edit_name:ident, $attr_name:expr, $internal_name:ident, $type:ty)),+]) => {
        $crate::impl_attr_getters_and_setters!(without_decoder $struct, [$(($getter_name, $setter_name, $in_place_edit_name, $attr_name, $internal_name, $type)),+]);
        $crate::impl_attr_getters_and_setters!(decoder $struct, [$(($getter_name, $setter_name, $in_place_edit_name, $attr_name, $internal_name, $type)),+]);
    };
}

pub fn parse_object<T: AttributeDecoder + 'static>(
    buf: &[u8],
    add_obj: u32,
    del_obj: u32,
) -> Result<(NfNetlinkAttributes, nfgenmsg, &[u8]), DecodeError> {
    debug!("parse_object() running");
    let (hdr, msg) = parse_nlmsg(buf)?;

    let op = get_operation_from_nlmsghdr_type(hdr.nlmsg_type) as u32;

    if op != add_obj && op != del_obj {
        return Err(DecodeError::UnexpectedType(hdr.nlmsg_type));
    }

    let obj_size = hdr.nlmsg_len as usize
        - pad_netlink_object_with_variable_size(size_of::<nlmsghdr>() + size_of::<nfgenmsg>());

    let remaining_data_offset = pad_netlink_object_with_variable_size(hdr.nlmsg_len as usize);
    let remaining_data = &buf[remaining_data_offset..];

    let (nfgenmsg, attrs) = match msg {
        NlMsg::NfGenMsg(nfgenmsg, content) => {
            (nfgenmsg, NfNetlinkAttributeReader::new(content, obj_size)?)
        }
        _ => return Err(DecodeError::UnexpectedType(hdr.nlmsg_type)),
    };

    let inner = attrs.decode::<T>()?;

    Ok((inner, nfgenmsg, remaining_data))
}
