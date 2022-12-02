use super::{Expression, ExpressionError};
use crate::create_wrapper_type;
use crate::sys;

// A Log expression will log all packets that match the rule.
create_wrapper_type!(
    inline: Log,
    [
        (
            get_group,
            set_group,
            with_group,
            sys::NFTA_LOG_GROUP,
            group,
            u32
        ),
        (
            get_prefix,
            set_prefix,
            with_prefix,
            sys::NFTA_LOG_PREFIX,
            prefix,
            String
        )
    ]
);

impl Log {
    pub fn new(
        group: Option<u16>,
        prefix: Option<impl Into<String>>,
    ) -> Result<Log, ExpressionError> {
        let mut res = Log::default();
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
}
