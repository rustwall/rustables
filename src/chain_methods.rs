use crate::{Batch, Chain, Hook, MsgType, Policy, Table};
use std::ffi::CString;
use std::rc::Rc;


/// A helper trait over [`rustables::Chain`].
pub trait ChainMethods {
    /// Create a new Chain instance from a [`rustables::Hook`] over a [`rustables::Table`].
    fn from_hook(hook: Hook, table: Rc<Table>) -> Self
        where Self: std::marker::Sized;
    /// Add a [`rustables::Policy`] to the current Chain.
    fn verdict(self, policy: Policy) -> Self;
    fn add_to_batch(self, batch: &mut Batch) -> Self;
}


impl ChainMethods for Chain {
    fn from_hook(hook: Hook, table: Rc<Table>) -> Self {
        let chain_name = match hook {
            Hook::PreRouting => "prerouting",
            Hook::Out => "out",
            Hook::PostRouting => "postrouting",
            Hook::Forward => "forward",
            Hook::In => "in",
        };
        let chain_name = CString::new(chain_name).unwrap();
        let mut chain = Chain::new(&chain_name, table);
        chain.set_hook(hook, 0);
        chain
    }
    fn verdict(mut self, policy: Policy) -> Self {
        self.set_policy(policy);
        self
    }
    fn add_to_batch(self, batch: &mut Batch) -> Self {
        batch.add(&self, MsgType::Add);
        self
    }
}

