use libc::{NF_ACCEPT, NF_DROP};

use crate::nlmsg::{
    NfNetlinkAttribute, NfNetlinkAttributes, NfNetlinkDeserializable, NfNetlinkObject,
    NfNetlinkWriter,
};
use crate::parser::{parse_object, DecodeError, InnerFormat, NfNetlinkAttributeReader};
use crate::sys::{self, NFT_MSG_DELCHAIN, NFT_MSG_NEWCHAIN, NLM_F_ACK, NLM_F_CREATE};
use crate::{impl_attr_getters_and_setters, MsgType, ProtocolFamily, Table};
use std::convert::TryFrom;
use std::fmt::Debug;

pub type ChainPriority = i32;

/// The netfilter event hooks a chain can register for.
#[derive(Debug, Copy, Clone, Eq, PartialEq, PartialOrd, Ord, Hash)]
#[repr(i32)]
pub enum HookClass {
    /// Hook into the pre-routing stage of netfilter. Corresponds to `NF_INET_PRE_ROUTING`.
    PreRouting = libc::NF_INET_PRE_ROUTING,
    /// Hook into the input stage of netfilter. Corresponds to `NF_INET_LOCAL_IN`.
    In = libc::NF_INET_LOCAL_IN,
    /// Hook into the forward stage of netfilter. Corresponds to `NF_INET_FORWARD`.
    Forward = libc::NF_INET_FORWARD,
    /// Hook into the output stage of netfilter. Corresponds to `NF_INET_LOCAL_OUT`.
    Out = libc::NF_INET_LOCAL_OUT,
    /// Hook into the post-routing stage of netfilter. Corresponds to `NF_INET_POST_ROUTING`.
    PostRouting = libc::NF_INET_POST_ROUTING,
}

#[derive(Clone, PartialEq, Eq)]
pub struct Hook {
    inner: NfNetlinkAttributes,
}

impl Hook {
    pub fn new(class: HookClass, priority: ChainPriority) -> Self {
        Hook {
            inner: NfNetlinkAttributes::new(),
        }
        .with_class(class as u32)
        .with_priority(priority as u32)
    }
}

impl Debug for Hook {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.inner_format_struct(f.debug_struct("Hook"))?.finish()
    }
}

impl_attr_getters_and_setters!(
    Hook,
    [
        // Define the action netfilter will apply to packets processed by this chain, but that did not match any rules in it.
        (
            get_class,
            set_class,
            with_class,
            sys::NFTA_HOOK_HOOKNUM,
            U32,
            u32
        ),
        (
            get_priority,
            set_priority,
            with_priority,
            sys::NFTA_HOOK_PRIORITY,
            U32,
            u32
        )
    ]
);

impl NfNetlinkAttribute for Hook {
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

impl NfNetlinkDeserializable for Hook {
    fn deserialize(buf: &[u8]) -> Result<(Self, &[u8]), DecodeError> {
        let reader = NfNetlinkAttributeReader::new(buf, buf.len())?;
        let inner = reader.decode::<Self>()?;
        Ok((Hook { inner }, &[]))
    }
}

/// A chain policy. Decides what to do with a packet that was processed by the chain but did not
/// match any rules.
#[derive(Debug, Copy, Clone, Eq, PartialEq, PartialOrd, Ord, Hash)]
#[repr(i32)]
pub enum ChainPolicy {
    /// Accept the packet.
    Accept = NF_ACCEPT,
    /// Drop the packet.
    Drop = NF_DROP,
}

impl NfNetlinkAttribute for ChainPolicy {
    fn get_size(&self) -> usize {
        (*self as i32).get_size()
    }

    unsafe fn write_payload(&self, addr: *mut u8) {
        (*self as i32).write_payload(addr);
    }
}

impl NfNetlinkDeserializable for ChainPolicy {
    fn deserialize(buf: &[u8]) -> Result<(Self, &[u8]), DecodeError> {
        let (v, remaining_data) = i32::deserialize(buf)?;
        Ok((
            match v {
                NF_ACCEPT => ChainPolicy::Accept,
                NF_DROP => ChainPolicy::Accept,
                _ => return Err(DecodeError::UnknownChainPolicy),
            },
            remaining_data,
        ))
    }
}

/// Base chain type.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub enum ChainType {
    /// Used to filter packets.
    /// Supported protocols: ip, ip6, inet, arp, and bridge tables.
    Filter,
    /// Used to reroute packets if IP headers or packet marks are modified.
    /// Supported protocols: ip, and ip6 tables.
    Route,
    /// Used to perform NAT.
    /// Supported protocols: ip, and ip6 tables.
    Nat,
}

impl ChainType {
    fn as_str(&self) -> &'static str {
        match *self {
            ChainType::Filter => "filter",
            ChainType::Route => "route",
            ChainType::Nat => "nat",
        }
    }
}

impl NfNetlinkAttribute for ChainType {
    fn get_size(&self) -> usize {
        self.as_str().len()
    }

    unsafe fn write_payload(&self, addr: *mut u8) {
        self.as_str().to_string().write_payload(addr);
    }
}

impl NfNetlinkDeserializable for ChainType {
    fn deserialize(buf: &[u8]) -> Result<(Self, &[u8]), DecodeError> {
        let (s, remaining_data) = String::deserialize(buf)?;
        Ok((
            match s.as_str() {
                "filter" => ChainType::Filter,
                "route" => ChainType::Route,
                "nat" => ChainType::Nat,
                _ => return Err(DecodeError::UnknownChainType),
            },
            remaining_data,
        ))
    }
}

/// Abstraction of a `nftnl_chain`. Chains reside inside [`Table`]s and they hold [`Rule`]s.
///
/// There are two types of chains, "base chain" and "regular chain". See [`set_hook`] for more
/// details.
///
/// [`Table`]: struct.Table.html
/// [`Rule`]: struct.Rule.html
/// [`set_hook`]: #method.set_hook
#[derive(PartialEq, Eq)]
pub struct Chain {
    family: ProtocolFamily,
    inner: NfNetlinkAttributes,
}

impl Chain {
    /// Creates a new chain instance inside the given [`Table`].
    ///
    /// [`Table`]: struct.Table.html
    pub fn new(table: &Table) -> Chain {
        let mut chain = Chain {
            family: table.get_family(),
            inner: NfNetlinkAttributes::new(),
        };

        if let Some(table_name) = table.get_name() {
            chain.set_table(table_name);
        }

        chain
    }

    pub fn get_family(&self) -> ProtocolFamily {
        self.family
    }

    fn raw_attributes(&self) -> &NfNetlinkAttributes {
        &self.inner
    }

    /*
    /// Returns a textual description of the chain.
    pub fn get_str(&self) -> CString {
        let mut descr_buf = vec![0i8; 4096];
        unsafe {
            sys::nftnl_chain_snprintf(
                descr_buf.as_mut_ptr() as *mut c_char,
                (descr_buf.len() - 1) as u64,
                self.chain,
                sys::NFTNL_OUTPUT_DEFAULT,
                0,
            );
            CStr::from_ptr(descr_buf.as_ptr() as *mut c_char).to_owned()
        }
    }
    */
}

/*
impl PartialEq for Chain {
    fn eq(&self, other: &Self) -> bool {
        self.get_table() == other.get_table() && self.get_name() == other.get_name()
    }
}
*/

impl Debug for Chain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut res = f.debug_struct("Chain");
        res.field("family", &self.family);
        self.inner_format_struct(res)?.finish()
    }
}

impl NfNetlinkObject for Chain {
    fn add_or_remove<'a>(&self, writer: &mut NfNetlinkWriter<'a>, msg_type: MsgType, seq: u32) {
        let raw_msg_type = match msg_type {
            MsgType::Add => NFT_MSG_NEWCHAIN,
            MsgType::Del => NFT_MSG_DELCHAIN,
        } as u16;
        writer.write_header(
            raw_msg_type,
            self.family,
            (if let MsgType::Add = msg_type {
                NLM_F_CREATE
            } else {
                0
            } | NLM_F_ACK) as u16,
            seq,
            None,
        );
        self.inner.serialize(writer);
        writer.finalize_writing_object();
    }
}

impl NfNetlinkDeserializable for Chain {
    fn deserialize(buf: &[u8]) -> Result<(Self, &[u8]), DecodeError> {
        let (inner, nfgenmsg, remaining_data) =
            parse_object::<Self>(buf, NFT_MSG_NEWCHAIN, NFT_MSG_DELCHAIN)?;

        Ok((
            Self {
                inner,
                family: ProtocolFamily::try_from(nfgenmsg.nfgen_family as i32)?,
            },
            remaining_data,
        ))
    }
}

impl_attr_getters_and_setters!(
    Chain,
    [
        (get_flags, set_flags, with_flags, sys::NFTA_CHAIN_FLAGS, U32, u32),
        (get_name, set_name, with_name, sys::NFTA_CHAIN_NAME, String, String),
        // Sets the hook and priority for this chain. Without calling this method the chain will
        // become a "regular chain" without any hook and will thus not receive any traffic unless
        // some rule forward packets to it via goto or jump verdicts.
        //
        // By calling `set_hook` with a hook the chain that is created will be registered with that
        // hook and is thus a "base chain". A "base chain" is an entry point for packets from the
        // networking stack.
        (get_hook, set_hook, with_hook, sys::NFTA_CHAIN_HOOK, ChainHook, Hook),
        (get_policy, set_policy, with_policy, sys::NFTA_CHAIN_POLICY, ChainPolicy, ChainPolicy),
        (get_table, set_table, with_table, sys::NFTA_CHAIN_TABLE, String, String),
        // This only applies if the chain has been registered with a hook by calling `set_hook`.
        (get_type, set_type, with_type, sys::NFTA_CHAIN_TYPE, ChainType, ChainType),
        (
            get_userdata,
            set_userdata,
            with_userdata,
            sys::NFTA_CHAIN_USERDATA,
            VecU8,
            Vec<u8>
        )
    ]
);

pub fn list_chains_for_table(table: &Table) -> Result<Vec<Chain>, crate::query::Error> {
    let mut result = Vec::new();
    crate::query::list_objects_with_data(
        libc::NFT_MSG_GETCHAIN as u16,
        &|chain: Chain, (table, chains): &mut (&Table, &mut Vec<Chain>)| {
            if chain.get_table() == table.get_name() {
                chains.push(chain);
            } else {
                info!(
                    "Ignoring chain {:?} because it doesn't map the table {:?}",
                    chain.get_name(),
                    table.get_name()
                );
            }
            Ok(())
        },
        None,
        &mut (&table, &mut result),
    )?;
    Ok(result)
}
