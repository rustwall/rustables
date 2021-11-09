use rustables::{Batch, Chain, ChainMethods, Direction, MatchError, ProtoFamily,
    Protocol, Rule, RuleMethods, Table, MsgType, Verdict};
use rustables::query::{send_batch, Error as QueryError};
use rustables::expr::{LogGroup, LogPrefix, LogPrefixError};
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
    #[error("Error encoding the prefix")]
    LogPrefixError(#[from] LogPrefixError),
}

const TABLE_NAME: &str = "main-table";


fn main() -> Result<(), Error> {
    let fw = Firewall::new()?;
    fw.start()?;
    Ok(())
}


/// An example firewall. See the source of its `start()` method.
pub struct Firewall {
    batch: Batch,
    inbound: Rc<Chain>,
    _outbound: Rc<Chain>,
    _forward: Rc<Chain>,
    _table: Rc<Table>,
}

impl Firewall {
    pub fn new() -> Result<Self, Error> {
        let mut batch = Batch::new();
        let _table = Rc::new(
            Table::new(&CString::new(TABLE_NAME)?, ProtoFamily::Inet)
        );
        batch.add(&_table, MsgType::Add);

        // Create base chains. Base chains are hooked into a Direction/Hook.
        let inbound = Rc::new(
            Chain::from_direction(&Direction::Inbound, Rc::clone(&_table))?
                  .verdict(&Verdict::Drop)
                  .add_to_batch(&mut batch)
        );
        let _outbound = Rc::new(
            Chain::from_direction(&Direction::Outbound, Rc::clone(&_table))?
                  .verdict(&Verdict::Accept)
                  .add_to_batch(&mut batch)
        );
        let _forward = Rc::new(
            Chain::from_direction(&Direction::Forward, Rc::clone(&_table))?
                  .verdict(&Verdict::Accept)
                  .add_to_batch(&mut batch)
        );

        Ok(Firewall {
            _table,
            batch,
            inbound,
            _outbound,
            _forward
        })
    }
    /// Allow some common-sense exceptions to inbound drop, and accept outbound and forward.
    pub fn start(mut self) -> Result<(), Error> {
        // Allow all established connections to get in.
        Rule::new(Rc::clone(&self.inbound))
             .established()
             .accept()
             .add_to_batch(&mut self.batch);
        // Allow all traffic on the loopback interface.
        Rule::new(Rc::clone(&self.inbound))
             .iface("lo")?
             .accept()
             .add_to_batch(&mut self.batch);
        // Allow ssh from anywhere, and log to dmesg with a prefix.
        Rule::new(Rc::clone(&self.inbound))
             .dport("22", &Protocol::TCP)?
             .accept()
             .log(None, Some(LogPrefix::new("allow ssh connection:")?))
             .add_to_batch(&mut self.batch);

        // Allow http from all IPs in 192.168.1.255/24 .
        let local_net = IpNetwork::new([192, 168, 1, 0].into(), 24).unwrap();
        Rule::new(Rc::clone(&self.inbound))
             .dport("80", &Protocol::TCP)?
             .snetwork(local_net)
             .accept()
             .add_to_batch(&mut self.batch);

        // Allow ICMP traffic, drop IGMP.
        Rule::new(Rc::clone(&self.inbound))
             .icmp()
             .accept()
             .add_to_batch(&mut self.batch);
        Rule::new(Rc::clone(&self.inbound))
             .igmp()
             .drop()
             .add_to_batch(&mut self.batch);

        // Log all traffic not accepted to NF_LOG group 1, accessible with ulogd.
        Rule::new(Rc::clone(&self.inbound))
             .log(Some(LogGroup(1)), None)
             .add_to_batch(&mut self.batch);

        let mut finalized_batch = self.batch.finalize().unwrap();
        send_batch(&mut finalized_batch)?;
        println!("table {} commited", TABLE_NAME);
        Ok(())
    }
    /// If there is any table with name TABLE_NAME, remove it.
    pub fn stop(mut self) -> Result<(), Error> {
        self.batch.add(&self._table, MsgType::Add);
        self.batch.add(&self._table, MsgType::Del);

        let mut finalized_batch = self.batch.finalize().unwrap();
        send_batch(&mut finalized_batch)?;
        println!("table {} destroyed", TABLE_NAME);
        Ok(())
    }
}


