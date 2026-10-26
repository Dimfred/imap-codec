//! Gmail IMAP Extensions (X-GM-EXT-1)
//!
//! See <https://developers.google.com/workspace/gmail/imap/imap-extensions>.
//!
//! This extends ...
//!
//! * [`MessageDataItemName`](crate::fetch::MessageDataItemName) with new variants:
//!
//!     - [`MessageDataItemName::XGmMsgId`](crate::fetch::MessageDataItemName::XGmMsgId)
//!     - [`MessageDataItemName::XGmThrId`](crate::fetch::MessageDataItemName::XGmThrId)
//!     - [`MessageDataItemName::XGmLabels`](crate::fetch::MessageDataItemName::XGmLabels)
//!
//! * [`MessageDataItem`](crate::fetch::MessageDataItem) with new variants:
//!
//!     - [`MessageDataItem::XGmMsgId`](crate::fetch::MessageDataItem::XGmMsgId)
//!     - [`MessageDataItem::XGmThrId`](crate::fetch::MessageDataItem::XGmThrId)
//!     - [`MessageDataItem::XGmLabels`](crate::fetch::MessageDataItem::XGmLabels)

#[cfg(feature = "arbitrary")]
use arbitrary::Arbitrary;
use bounded_static_derive::ToStatic;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::core::{AString, Atom};

/// A Gmail label as returned in `X-GM-LABELS`.
#[cfg_attr(feature = "arbitrary", derive(Arbitrary))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq, Hash, ToStatic)]
pub enum XGmLabel<'a> {
    /// A system label, e.g., `\Inbox`, `\Sent`, or `\Important`.
    ///
    /// The atom is stored without the leading backslash.
    System(Atom<'a>),
    /// A user label, e.g., `Important` or `"Muy Importante"`.
    Other(AString<'a>),
}
