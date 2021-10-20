use crate::expr::ExpressionWrapper;
use crate::{chain::Chain, expr::Expression, MsgType};
use rustables_sys::{self as sys, libc};
use std::ffi::{c_void, CStr, CString};
use std::fmt::Debug;
use std::os::raw::c_char;
use std::rc::Rc;

/// A nftables firewall rule.
pub struct Rule {
    pub(crate) rule: *mut sys::nftnl_rule,
    pub(crate) chain: Rc<Chain>,
}

impl Rule {
    /// Creates a new rule object in the given [`Chain`].
    ///
    /// [`Chain`]: struct.Chain.html
    pub fn new(chain: Rc<Chain>) -> Rule {
        unsafe {
            let rule = try_alloc!(sys::nftnl_rule_alloc());
            sys::nftnl_rule_set_u32(
                rule,
                sys::NFTNL_RULE_FAMILY as u16,
                chain.get_table().get_family() as u32,
            );
            sys::nftnl_rule_set_str(
                rule,
                sys::NFTNL_RULE_TABLE as u16,
                chain.get_table().get_name().as_ptr(),
            );
            sys::nftnl_rule_set_str(
                rule,
                sys::NFTNL_RULE_CHAIN as u16,
                chain.get_name().as_ptr(),
            );

            Rule { rule, chain }
        }
    }

    pub unsafe fn from_raw(rule: *mut sys::nftnl_rule, chain: Rc<Chain>) -> Self {
        Rule { rule, chain }
    }

    pub fn get_position(&self) -> u64 {
        unsafe { sys::nftnl_rule_get_u64(self.rule, sys::NFTNL_RULE_POSITION as u16) }
    }

    /// Sets the position of this rule within the chain it lives in. By default a new rule is added
    /// to the end of the chain.
    pub fn set_position(&mut self, position: u64) {
        unsafe {
            sys::nftnl_rule_set_u64(self.rule, sys::NFTNL_RULE_POSITION as u16, position);
        }
    }

    pub fn get_handle(&self) -> u64 {
        unsafe { sys::nftnl_rule_get_u64(self.rule, sys::NFTNL_RULE_HANDLE as u16) }
    }

    pub fn set_handle(&mut self, handle: u64) {
        unsafe {
            sys::nftnl_rule_set_u64(self.rule, sys::NFTNL_RULE_HANDLE as u16, handle);
        }
    }

    /// Adds an expression to this rule. Expressions are evaluated from first to last added.
    /// As soon as an expression does not match the packet it's being evaluated for, evaluation
    /// stops and the packet is evaluated against the next rule in the chain.
    pub fn add_expr(&mut self, expr: &impl Expression) {
        unsafe { sys::nftnl_rule_add_expr(self.rule, expr.to_expr(self)) }
    }

    /// Returns a reference to the [`Chain`] this rule lives in.
    ///
    /// [`Chain`]: struct.Chain.html
    pub fn get_chain(&self) -> Rc<Chain> {
        self.chain.clone()
    }

    /// Returns the userdata of this chain.
    pub fn get_userdata(&self) -> Option<&CStr> {
        unsafe {
            let ptr = sys::nftnl_rule_get_str(self.rule, sys::NFTNL_RULE_USERDATA as u16);
            if ptr == std::ptr::null() {
                return None;
            }
            Some(CStr::from_ptr(ptr))
        }
    }

    /// Updates the userdata of this chain.
    pub fn set_userdata(&self, data: &CStr) {
        unsafe {
            sys::nftnl_rule_set_str(self.rule, sys::NFTNL_RULE_USERDATA as u16, data.as_ptr());
        }
    }

    /// Returns a textual description of the rule.
    pub fn get_str(&self) -> CString {
        let mut descr_buf = vec![0i8; 4096];
        unsafe {
            sys::nftnl_rule_snprintf(
                descr_buf.as_mut_ptr(),
                (descr_buf.len() - 1) as u64,
                self.rule,
                sys::NFTNL_OUTPUT_DEFAULT,
                0,
            );
            CStr::from_ptr(descr_buf.as_ptr()).to_owned()
        }
    }

    /// Retrieves an iterator to loop over the expressions of the rule
    pub fn get_exprs(self: &Rc<Self>) -> RuleExprsIter {
        RuleExprsIter::new(self.clone())
    }

    #[cfg(feature = "unsafe-raw-handles")]
    /// Returns the raw handle.
    pub fn as_ptr(&self) -> *const sys::nftnl_rule {
        self.rule as *const sys::nftnl_rule
    }

    #[cfg(feature = "unsafe-raw-handles")]
    /// Returns a mutable version of the raw handle.
    pub fn as_mut_ptr(&mut self) -> *mut sys::nftnl_rule {
        self.rule
    }
}

impl Debug for Rule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.get_str())
    }
}

impl PartialEq for Rule {
    fn eq(&self, other: &Self) -> bool {
        self.get_chain() == other.get_chain() && self.get_handle() == other.get_handle()
    }
}

unsafe impl crate::NlMsg for Rule {
    unsafe fn write(&self, buf: *mut c_void, seq: u32, msg_type: MsgType) {
        let type_ = match msg_type {
            MsgType::Add => libc::NFT_MSG_NEWRULE,
            MsgType::Del => libc::NFT_MSG_DELRULE,
        };
        let flags: u16 = match msg_type {
            MsgType::Add => (libc::NLM_F_CREATE | libc::NLM_F_APPEND | libc::NLM_F_EXCL) as u16,
            MsgType::Del => 0u16,
        } | libc::NLM_F_ACK as u16;
        let header = sys::nftnl_nlmsg_build_hdr(
            buf as *mut c_char,
            type_ as u16,
            self.chain.get_table().get_family() as u16,
            flags,
            seq,
        );
        sys::nftnl_rule_nlmsg_build_payload(header, self.rule);
    }
}

impl Drop for Rule {
    fn drop(&mut self) {
        unsafe { sys::nftnl_rule_free(self.rule) };
    }
}

pub struct RuleExprsIter {
    rule: Rc<Rule>,
    iter: *mut sys::nftnl_expr_iter,
}

impl RuleExprsIter {
    fn new(rule: Rc<Rule>) -> Self {
        let iter =
            try_alloc!(unsafe { sys::nftnl_expr_iter_create(rule.rule as *const sys::nftnl_rule) });
        RuleExprsIter { rule, iter }
    }
}

impl Iterator for RuleExprsIter {
    type Item = ExpressionWrapper;

    fn next(&mut self) -> Option<Self::Item> {
        let next = unsafe { sys::nftnl_expr_iter_next(self.iter) };
        if next.is_null() {
            trace!("RulesExprsIter iterator ending");
            None
        } else {
            trace!("RulesExprsIter returning new expression");
            Some(ExpressionWrapper {
                expr: next,
                rule: self.rule.clone(),
            })
        }
    }
}

impl Drop for RuleExprsIter {
    fn drop(&mut self) {
        unsafe { sys::nftnl_expr_iter_destroy(self.iter) };
    }
}

#[cfg(feature = "query")]
pub fn get_rules_cb(
    header: &libc::nlmsghdr,
    (chain, rules): &mut (&Rc<Chain>, &mut Vec<Rule>),
) -> libc::c_int {
    unsafe {
        let rule = sys::nftnl_rule_alloc();
        if rule == std::ptr::null_mut() {
            return mnl::mnl_sys::MNL_CB_ERROR;
        }
        let err = sys::nftnl_rule_nlmsg_parse(header, rule);
        if err < 0 {
            error!("Failed to parse nelink rule message - {}", err);
            sys::nftnl_rule_free(rule);
            return err;
        }

        rules.push(Rule::from_raw(rule, chain.clone()));
    }
    mnl::mnl_sys::MNL_CB_OK
}

#[cfg(feature = "query")]
pub fn list_rules_for_chain(chain: &Rc<Chain>) -> Result<Vec<Rule>, crate::query::Error> {
    crate::query::list_objects_with_data(
        libc::NFT_MSG_GETRULE as u16,
        get_rules_cb,
        &chain,
        // only retrieve rules from the currently targetted chain
        Some(&|hdr| unsafe {
            let rule = sys::nftnl_rule_alloc();
            if rule as *const _ == std::ptr::null() {
                return Err(crate::query::Error::NetlinkAllocationFailed);
            }

            sys::nftnl_rule_set_str(
                rule,
                sys::NFTNL_RULE_TABLE as u16,
                chain.get_table().get_name().as_ptr(),
            );
            sys::nftnl_rule_set_u32(
                rule,
                sys::NFTNL_RULE_FAMILY as u16,
                chain.get_table().get_family() as u32,
            );
            sys::nftnl_rule_set_str(
                rule,
                sys::NFTNL_RULE_CHAIN as u16,
                chain.get_name().as_ptr(),
            );

            sys::nftnl_rule_nlmsg_build_payload(hdr, rule);

            sys::nftnl_rule_free(rule);
            Ok(())
        }),
    )
}
