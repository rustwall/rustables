use super::{Expression, Rule};
use rustables_sys as sys;
use std::os::raw::c_char;
use std::ffi::CString;

/// A Log expression will log all packets that match the rule.
pub struct Log {
    pub group: Option<LogGroup>,
    pub prefix: Option<LogPrefix>
}

impl Expression for Log {
    fn to_expr(&self, _rule: &Rule) -> *mut sys::nftnl_expr {
        unsafe {
            let expr = try_alloc!(sys::nftnl_expr_alloc(
                b"log\0" as *const _ as *const c_char
            ));
            if let Some(log_group) = self.group {
                sys::nftnl_expr_set_u32(
                    expr,
                    sys::NFTNL_EXPR_LOG_GROUP as u16,
                    log_group.0 as u32,
                );
            };
            if let Some(LogPrefix(prefix)) = &self.prefix {
                sys::nftnl_expr_set_str(
                    expr,
                    sys::NFTNL_EXPR_LOG_PREFIX as u16,
                    prefix.as_ptr()
                );
            };

            expr
        }
    }
}


}

/// The NFLOG group that will be assigned to each log line.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub struct LogGroup(pub u16);

/// A prefix that will get prepended to each log line.
#[derive(Clone)]
pub struct LogPrefix(pub CString);

impl LogPrefix {
    /// Create a new LogPrefix from a String. Converts it to CString as needed by nftables.
    pub fn new(prefix: &str) -> Result<Self, std::ffi::NulError> {
        // TODO check for prefix size constraints.
        match CString::new(prefix) {
            Ok(string) => Ok(LogPrefix(string)),
            Err(error)=> Err(error)
        }
    }
}


#[macro_export]
macro_rules! nft_expr_log {
    (group $group:ident prefix $prefix:expr) => {
        $crate::expr::Log { group: $group, prefix: $prefix }
    };
    (prefix $prefix:expr) => {
        $crate::expr::Log { group: None, prefix: $prefix }
    };
    (group $group:ident) => {
        $crate::expr::Log { group: $group, prefix: None }
    };
    () => {
        $crate::expr::Log { group: None, prefix: None }
    };
}
