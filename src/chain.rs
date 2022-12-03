use libc::{NF_ACCEPT, NF_DROP};
use rustables_macros::nfnetlink_struct;

use crate::nlmsg::{NfNetlinkAttribute, NfNetlinkDeserializable, NfNetlinkObject, NfNetlinkWriter};
use crate::parser::{DecodeError, Parsable};
use crate::sys::{
    NFTA_CHAIN_FLAGS, NFTA_CHAIN_HOOK, NFTA_CHAIN_NAME, NFTA_CHAIN_POLICY, NFTA_CHAIN_TABLE,
    NFTA_CHAIN_TYPE, NFTA_CHAIN_USERDATA, NFTA_HOOK_HOOKNUM, NFTA_HOOK_PRIORITY, NFT_MSG_DELCHAIN,
    NFT_MSG_NEWCHAIN, NLM_F_ACK, NLM_F_CREATE,
};
use crate::{MsgType, ProtocolFamily, Table};
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

#[derive(Clone, PartialEq, Eq, Default, Debug)]
#[nfnetlink_struct(nested = true)]
pub struct Hook {
    /// Define the action netfilter will apply to packets processed by this chain, but that did not match any rules in it.
    #[field(NFTA_HOOK_HOOKNUM)]
    class: u32,
    #[field(NFTA_HOOK_PRIORITY)]
    priority: u32,
}

impl Hook {
    pub fn new(class: HookClass, priority: ChainPriority) -> Self {
        Hook::default()
            .with_class(class as u32)
            .with_priority(priority as u32)
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
#[derive(PartialEq, Eq, Default, Debug)]
#[nfnetlink_struct(derive_deserialize = false)]
pub struct Chain {
    family: ProtocolFamily,
    #[field(NFTA_CHAIN_TABLE)]
    table: String,
    #[field(NFTA_CHAIN_NAME)]
    name: String,
    #[field(NFTA_CHAIN_HOOK)]
    hook: Hook,
    #[field(NFTA_CHAIN_POLICY)]
    policy: ChainPolicy,
    #[field(NFTA_CHAIN_TYPE, name_in_functions = "type")]
    chain_type: ChainType,
    #[field(NFTA_CHAIN_FLAGS)]
    flags: u32,
    #[field(NFTA_CHAIN_USERDATA)]
    userdata: Vec<u8>,
}

impl Chain {
    /// Creates a new chain instance inside the given [`Table`].
    ///
    /// [`Table`]: struct.Table.html
    pub fn new(table: &Table) -> Chain {
        let mut chain = Chain::default();
        chain.family = table.family;

        if let Some(table_name) = table.get_name() {
            chain.set_table(table_name);
        }

        chain
    }

    pub fn get_family(&self) -> ProtocolFamily {
        self.family
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
        let buf = writer.add_data_zeroed(self.get_size());
        unsafe {
            self.write_payload(buf.as_mut_ptr());
        }
        writer.finalize_writing_object();
    }
}

impl NfNetlinkDeserializable for Chain {
    fn deserialize(buf: &[u8]) -> Result<(Self, &[u8]), DecodeError> {
        let (mut obj, nfgenmsg, remaining_data) =
            Self::parse_object(buf, NFT_MSG_NEWCHAIN, NFT_MSG_DELCHAIN)?;
        obj.family = ProtocolFamily::try_from(nfgenmsg.nfgen_family as i32)?;

        Ok((obj, remaining_data))
    }
}

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
