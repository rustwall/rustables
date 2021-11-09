use crate::{Batch, Chain, Hook, MsgType, Policy, Table};
use std::ffi::{CString, NulError};
use std::rc::Rc;

use serde::{Deserialize, Serialize};

/// A helper trait over [`rustables::Chain`].
pub trait ChainMethods {
    /// Create a new Chain instance from a [`Direction`] over a [`rustables::Table`].
    fn from_direction(direction: &Direction, table: Rc<Table>) -> Result<Self, NulError> where Self: std::marker::Sized;
    /// Add a [`Verdict`] to the current Chain.
    fn verdict(self, verdict: &Verdict) -> Self;
    fn add_to_batch(self, batch: &mut Batch) -> Self;
}

impl ChainMethods for Chain {
    fn from_direction(direction: &Direction, table: Rc<Table>) -> Result<Self, NulError> {
        let chain_name = CString::new(direction.display())?;
        let mut chain = Chain::new(&chain_name, table);
        chain.set_hook(direction.get_hook(), 0);
        Ok(chain)
    }
    fn verdict(mut self, verdict: &Verdict) -> Self {
        self.set_policy(verdict.get());
        self
    }
    fn add_to_batch(self, batch: &mut Batch) -> Self {
        batch.add(&self, MsgType::Add);
        self
    }
}

/// A Serializable wrapper type around [`rustables::Hook`].
#[derive(Serialize, Deserialize, Debug, Clone, Eq, PartialEq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    Inbound,
    Outbound,
    Forward
}
impl Direction {
    /// Return the Direction's [`rustables::Hook`], ie its representation inside rustables. Note that
    /// there are Hooks not represented here, namely Prerouting and Postrouting. File a bug if
    /// you need those.
    pub fn get_hook(&self) -> Hook {
        match self {
            Direction::Inbound => Hook::In,
            Direction::Outbound => Hook::Out,
            Direction::Forward => Hook::Forward,
        }
    }
    /// Return a string representation of the Direction.
    pub fn display(&self) -> String {
        let s = match self {
            Direction::Inbound => "inbound",
            Direction::Outbound => "outbound",
            Direction::Forward => "forward",
        };
        s.to_string()
    }
}
/// A Serializable wrapper type around [`rustables::Policy`].
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Accept,
    Drop
}
impl Verdict {
    /// Return the rustables representation of a Verdict (ie, a [`rustables::Policy`]).
    pub fn get(&self) -> Policy {
        match self {
            Verdict::Accept => Policy::Accept,
            Verdict::Drop => Policy::Drop,
        }
    }
}

