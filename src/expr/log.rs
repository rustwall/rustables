use super::{Expression, ExpressionError};
use crate::create_expr_type;
use crate::nlmsg::NfNetlinkAttributes;
use crate::sys;

// A Log expression will log all packets that match the rule.
create_expr_type!(
    inline with_builder : Log,
    [
        (
            get_group,
            set_group,
            with_group,
            sys::NFTA_LOG_GROUP,
            U32,
            u32
        ),
        (
            get_prefix,
            set_prefix,
            with_prefix,
            sys::NFTA_LOG_PREFIX,
            String,
            String
        )
    ]
);

impl Log {
    pub fn new(
        group: Option<u16>,
        prefix: Option<impl Into<String>>,
    ) -> Result<Log, ExpressionError> {
        let mut res = Log {
            inner: NfNetlinkAttributes::new(),
            //pub group: Option<LogGroup>,
            //pub prefix: Option<LogPrefix>,
        };
        if let Some(group) = group {
            res.set_group(group);
        }
        if let Some(prefix) = prefix {
            let prefix = prefix.into();

            if prefix.bytes().count() > 127 {
                return Err(ExpressionError::TooLongLogPrefix);
            }
            res.set_prefix(prefix);
        }
        Ok(res)
    }
}

impl Expression for Log {
    fn get_name() -> &'static str {
        "log"
    }
    /*
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
    */
}

#[macro_export]
macro_rules! nft_expr_log {
    (group $group:ident prefix $prefix:expr) => {
        $crate::expr::Log::new(Some($group), Some($prefix))
    };
    (prefix $prefix:expr) => {
        $crate::expr::Log::new(None, Some($prefix))
    };
    (group $group:ident) => {
        $crate::expr::Log::new(Some($group), None)
    };
    () => {
        $crate::expr::Log::new(None, None)
    };
}
