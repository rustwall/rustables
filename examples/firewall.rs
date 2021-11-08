use rustables::{Batch, Chain, Hook, Match, MatchError, Policy, Rule, Protocol, ProtoFamily, Table, MsgType, expr::LogGroup};
use rustables::query::{send_batch, Error as QueryError};
use ipnetwork::IpNetwork;
use std::ffi::{CString, NulError};
use std::str::Utf8Error;
use std::rc::Rc;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("Unable to open netlink socket to netfilter")]
    NetlinkOpenError(#[source] std::io::Error),
    #[error("Firewall is already started")]
    AlreadyDone,
    #[error("Error converting from a C String")]
    NulError(#[from] NulError),
    #[error("Error creating match")]
    MatchError(#[from] MatchError),
    #[error("Error converting to utf-8 string")]
    Utf8Error(#[from] Utf8Error),
    #[error("Error applying batch")]
    BatchError(#[from] std::io::Error),
    #[error("Error applying batch")]
    QueryError(#[from] QueryError),
}

const TABLE_NAME: &str = "main-table";

fn main() -> Result<(), Error> {
    let mut fw = Firewall::new()?;
    fw.start()?;
    Ok(())
}

pub struct Firewall {
    table: Rc<Table>
}

impl Firewall {
    pub fn new() -> Result<Self, Error> {
        let table = Rc::new(Table::new(
            &CString::new(TABLE_NAME)?,
            ProtoFamily::Inet
        ));
        Ok(Firewall { table })
    }
    /// Attempt to use the batch from the struct holding the table.
    pub fn allow_port(&mut self, port: &str, protocol: &Protocol, chain: Rc<Chain>, batch: &mut Batch) -> Result<(), Error> {
        let rule = Rule::new(chain).dport(port, protocol)?.accept().add_to_batch(batch);
        batch.add(&rule, MsgType::Add);
        Ok(())
    }
    /// Apply the current realm's batch.
    pub fn start(&mut self) -> Result<(), Error> {
        let mut batch = Batch::new();
        batch.add(&self.table, MsgType::Add);

        let local_net = IpNetwork::new([192, 168, 1, 0].into(), 24).unwrap();
        let mut inbound = Chain::new(&CString::new("in")?, Rc::clone(&self.table));
        inbound.set_hook(Hook::In, 0);
        inbound.set_policy(Policy::Drop);
        let inbound = Rc::new(inbound);
        batch.add(&inbound, MsgType::Add);
        let mut outbound = Chain::new(&CString::new("out")?, Rc::clone(&self.table));
        outbound.set_hook(Hook::Out, 0);
        outbound.set_policy(Policy::Accept);
        batch.add(&outbound, MsgType::Add);
        let mut forward = Chain::new(&CString::new("forward")?, Rc::clone(&self.table));
        forward.set_hook(Hook::Forward, 0);
        forward.set_policy(Policy::Accept);
        batch.add(&forward, MsgType::Add);
        Rule::new(Rc::clone(&inbound))
             .established()
             .accept()
             .add_to_batch(&mut batch);
        Rule::new(Rc::clone(&inbound))
             .iface("lo")?
             .accept()
             .add_to_batch(&mut batch);
        self.allow_port("22", &Protocol::TCP, Rc::clone(&inbound), &mut batch)?;
        Rule::new(Rc::clone(&inbound))
             .dport("80", &Protocol::TCP)?
             .snetwork(local_net)
             .accept()
             .add_to_batch(&mut batch);
        Rule::new(Rc::clone(&inbound))
             .icmp()
             .accept()
             .add_to_batch(&mut batch);
        Rule::new(Rc::clone(&inbound))
             .igmp()
             .drop()
             .add_to_batch(&mut batch);

        //use nftnl::expr::LogPrefix;
        //let prefix = "REALM=".to_string() + &self.realm_def.name;
        Rule::new(Rc::clone(&inbound))
             .log(Some(LogGroup(1)), None)
             //.log( Some(LogGroup(1)), Some(LogPrefix::new(&prefix)
             //       .expect("Could not convert log prefix string to CString")))
             .add_to_batch(&mut batch);

        let mut finalized_batch = batch.finalize().unwrap();
        send_batch(&mut finalized_batch)?;
        println!("ruleset applied");
        Ok(())
    }
    /// If there are any rulesets applied, remove them.
    pub fn stop(&mut self) -> Result<(), Error> {
        let table = Table::new(&CString::new(TABLE_NAME)?, ProtoFamily::Inet);
        let mut batch = Batch::new();
        batch.add(&table, MsgType::Add);
        batch.add(&table, MsgType::Del);
        Ok(())
    }
}

