use rustables_macros::nfnetlink_struct;

use crate::expr::ExpressionList;
use crate::nlmsg::{NfNetlinkAttribute, NfNetlinkDeserializable, NfNetlinkObject, NfNetlinkWriter};
use crate::parser::{DecodeError, Parsable};
use crate::query::list_objects_with_data;
use crate::sys::{
    NFTA_RULE_CHAIN, NFTA_RULE_EXPRESSIONS, NFTA_RULE_HANDLE, NFTA_RULE_ID, NFTA_RULE_POSITION,
    NFTA_RULE_TABLE, NFTA_RULE_USERDATA, NFT_MSG_DELRULE, NFT_MSG_NEWRULE, NLM_F_ACK, NLM_F_CREATE,
};
use crate::ProtocolFamily;
use crate::{chain::Chain, MsgType};
use std::convert::TryFrom;
use std::fmt::Debug;

/// A nftables firewall rule.
#[derive(Clone, PartialEq, Eq, Default, Debug)]
#[nfnetlink_struct(derive_deserialize = false)]
pub struct Rule {
    #[field(NFTA_RULE_TABLE)]
    table: String,
    #[field(NFTA_RULE_CHAIN)]
    chain: String,
    #[field(NFTA_RULE_HANDLE)]
    handle: u64,
    #[field(NFTA_RULE_EXPRESSIONS)]
    expressions: ExpressionList,
    #[field(NFTA_RULE_POSITION)]
    position: u64,
    #[field(NFTA_RULE_USERDATA)]
    userdata: Vec<u8>,
    #[field(NFTA_RULE_ID)]
    id: u32,
    family: ProtocolFamily,
}

impl Rule {
    /// Creates a new rule object in the given [`Chain`].
    ///
    /// [`Chain`]: struct.Chain.html
    pub fn new(chain: &Chain) -> Result<Rule, DecodeError> {
        Ok(Rule::default()
            .with_family(chain.get_family())
            .with_table(
                chain
                    .get_table()
                    .ok_or(DecodeError::MissingChainInformationError)?,
            )
            .with_chain(
                chain
                    .get_name()
                    .ok_or(DecodeError::MissingChainInformationError)?,
            ))
    }

    pub fn get_family(&self) -> ProtocolFamily {
        self.family
    }

    pub fn set_family(&mut self, family: ProtocolFamily) {
        self.family = family;
    }

    pub fn with_family(mut self, family: ProtocolFamily) -> Self {
        self.set_family(family);
        self
    }
}

impl NfNetlinkObject for Rule {
    fn add_or_remove<'a>(&self, writer: &mut NfNetlinkWriter<'a>, msg_type: MsgType, seq: u32) {
        let raw_msg_type = match msg_type {
            MsgType::Add => NFT_MSG_NEWRULE,
            MsgType::Del => NFT_MSG_DELRULE,
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

impl NfNetlinkDeserializable for Rule {
    fn deserialize(buf: &[u8]) -> Result<(Self, &[u8]), DecodeError> {
        let (mut obj, nfgenmsg, remaining_data) =
            Self::parse_object(buf, NFT_MSG_NEWRULE, NFT_MSG_DELRULE)?;
        obj.family = ProtocolFamily::try_from(nfgenmsg.nfgen_family as i32)?;

        Ok((obj, remaining_data))
    }
}

pub fn list_rules_for_chain(chain: &Chain) -> Result<Vec<Rule>, crate::query::Error> {
    let mut result = Vec::new();
    list_objects_with_data(
        libc::NFT_MSG_GETRULE as u16,
        &|rule: Rule, rules: &mut Vec<Rule>| {
            rules.push(rule);
            Ok(())
        },
        // only retrieve rules from the currently targetted chain
        Some(&Rule::new(chain)?),
        &mut result,
    )?;
    Ok(result)
}
