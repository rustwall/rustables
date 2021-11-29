use super::{DeserializationError, Expression, Rule};
use crate::sys;
use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use thiserror::Error;

/// A Log expression will log all packets that match the rule.
#[derive(Debug, PartialEq)]
pub struct Log {
    pub group: Option<LogGroup>,
    pub prefix: Option<LogPrefix>,
}

impl Expression for Log {
    fn get_raw_name() -> *const sys::libc::c_char {
        b"log\0" as *const _ as *const c_char
    }

    fn from_expr(expr: *const sys::nftnl_expr) -> Result<Self, DeserializationError>
    where
        Self: Sized,
    {
        unsafe {
            let mut group = None;
            if sys::nftnl_expr_is_set(expr, sys::NFTNL_EXPR_LOG_GROUP as u16) {
                group = Some(LogGroup(sys::nftnl_expr_get_u32(
                    expr,
                    sys::NFTNL_EXPR_LOG_GROUP as u16,
                ) as u16));
            }
            let mut prefix = None;
            if sys::nftnl_expr_is_set(expr, sys::NFTNL_EXPR_LOG_PREFIX as u16) {
                let raw_prefix = sys::nftnl_expr_get_str(expr, sys::NFTNL_EXPR_LOG_PREFIX as u16);
                if raw_prefix.is_null() {
                    return Err(DeserializationError::NullPointer);
                } else {
                    prefix = Some(LogPrefix(CStr::from_ptr(raw_prefix).to_owned()));
                }
            }
            Ok(Log { group, prefix })
        }
    }

    fn to_expr(&self, _rule: &Rule) -> *mut sys::nftnl_expr {
        unsafe {
            let expr = try_alloc!(sys::nftnl_expr_alloc(b"log\0" as *const _ as *const c_char));
            if let Some(log_group) = self.group {
                sys::nftnl_expr_set_u32(expr, sys::NFTNL_EXPR_LOG_GROUP as u16, log_group.0 as u32);
            };
            if let Some(LogPrefix(prefix)) = &self.prefix {
                sys::nftnl_expr_set_str(expr, sys::NFTNL_EXPR_LOG_PREFIX as u16, prefix.as_ptr());
            };

            expr
        }
    }
}

#[derive(Error, Debug)]
pub enum LogPrefixError {
    #[error("The log prefix string is more than 128 characters long")]
    TooLongPrefix,
    #[error("The log prefix string contains an invalid Nul character.")]
    PrefixContainsANul(#[from] std::ffi::NulError),
}

/// The NFLOG group that will be assigned to each log line.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub struct LogGroup(pub u16);

/// A prefix that will get prepended to each log line.
#[derive(Debug, Clone, PartialEq)]
pub struct LogPrefix(CString);

impl LogPrefix {
    /// Creates a new LogPrefix from a String. Converts it to CString as needed by nftnl. Note that
    /// LogPrefix should not be more than 127 characters long.
    pub fn new(prefix: &str) -> Result<Self, LogPrefixError> {
        if prefix.chars().count() > 127 {
            return Err(LogPrefixError::TooLongPrefix);
        }
        Ok(LogPrefix(CString::new(prefix)?))
    }
}

#[macro_export]
macro_rules! nft_expr_log {
    (group $group:ident prefix $prefix:expr) => {
        $crate::expr::Log {
            group: $group,
            prefix: $prefix,
        }
    };
    (prefix $prefix:expr) => {
        $crate::expr::Log {
            group: None,
            prefix: $prefix,
        }
    };
    (group $group:ident) => {
        $crate::expr::Log {
            group: $group,
            prefix: None,
        }
    };
    () => {
        $crate::expr::Log {
            group: None,
            prefix: None,
        }
    };
}
