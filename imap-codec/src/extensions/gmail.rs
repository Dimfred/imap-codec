//! Gmail IMAP Extensions (X-GM-EXT-1)

use std::io::Write;

use abnf_core::streaming::sp;
use imap_types::{
    extensions::gmail::XGmLabel,
    fetch::{MessageDataItem, MessageDataItemName},
};
use nom::{
    branch::alt,
    bytes::streaming::tag_no_case,
    character::streaming::char,
    combinator::{map, opt, value},
    multi::separated_list1,
    sequence::{delimited, preceded},
};

use crate::{
    core::{astring, atom, number64},
    decode::IMAPResult,
    encode::{EncodeContext, EncodeIntoContext},
};

/// ```abnf
/// x-gm-fetch-att = "X-GM-MSGID" / "X-GM-THRID" / "X-GM-LABELS"
/// ```
pub(crate) fn x_gm_fetch_att(input: &[u8]) -> IMAPResult<&[u8], MessageDataItemName> {
    alt((
        value(MessageDataItemName::XGmMsgId, tag_no_case(b"X-GM-MSGID")),
        value(MessageDataItemName::XGmThrId, tag_no_case(b"X-GM-THRID")),
        value(MessageDataItemName::XGmLabels, tag_no_case(b"X-GM-LABELS")),
    ))(input)
}

/// ```abnf
/// x-gm-msg-att = "X-GM-MSGID" SP number64 /
///                "X-GM-THRID" SP number64 /
///                "X-GM-LABELS" SP "(" [x-gm-label *(SP x-gm-label)] ")"
/// ```
pub(crate) fn x_gm_msg_att(input: &[u8]) -> IMAPResult<&[u8], MessageDataItem> {
    alt((
        map(
            preceded(tag_no_case(b"X-GM-MSGID "), number64),
            MessageDataItem::XGmMsgId,
        ),
        map(
            preceded(tag_no_case(b"X-GM-THRID "), number64),
            MessageDataItem::XGmThrId,
        ),
        map(
            preceded(
                tag_no_case(b"X-GM-LABELS "),
                delimited(char('('), opt(separated_list1(sp, x_gm_label)), char(')')),
            ),
            |labels| MessageDataItem::XGmLabels(labels.unwrap_or_default()),
        ),
    ))(input)
}

/// ```abnf
/// x-gm-label = "\" atom / astring
/// ```
pub(crate) fn x_gm_label(input: &[u8]) -> IMAPResult<&[u8], XGmLabel> {
    alt((
        map(preceded(char('\\'), atom), XGmLabel::System),
        map(astring, XGmLabel::Other),
    ))(input)
}

impl EncodeIntoContext for XGmLabel<'_> {
    fn encode_ctx(&self, ctx: &mut EncodeContext) -> std::io::Result<()> {
        match self {
            XGmLabel::System(atom) => {
                ctx.write_all(b"\\")?;
                atom.encode_ctx(ctx)
            }
            XGmLabel::Other(astring) => astring.encode_ctx(ctx),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU32;

    use imap_types::{
        command::{Command, CommandBody},
        core::{AString, Atom, Vec1},
        response::{Data, Response},
    };

    use super::*;
    use crate::testing::{kat_inverse_command, kat_inverse_response, known_answer_test_encode};

    fn fetch_response(items: Vec<MessageDataItem<'static>>) -> Response<'static> {
        Response::Data(Data::Fetch {
            seq: NonZeroU32::new(1).unwrap(),
            items: Vec1::try_from(items).unwrap(),
        })
    }

    #[test]
    fn test_kat_inverse_response_x_gm() {
        kat_inverse_response(&[
            (
                b"* 1 FETCH (X-GM-MSGID 1278455344230334865 X-GM-THRID 1266894439832287888 X-GM-LABELS (\\Inbox \\Sent Important \"Muy Importante\"))\r\n".as_ref(),
                b"".as_ref(),
                fetch_response(vec![
                    MessageDataItem::XGmMsgId(1278455344230334865),
                    MessageDataItem::XGmThrId(1266894439832287888),
                    MessageDataItem::XGmLabels(vec![
                        XGmLabel::System(Atom::try_from("Inbox").unwrap()),
                        XGmLabel::System(Atom::try_from("Sent").unwrap()),
                        XGmLabel::Other(AString::try_from("Important").unwrap()),
                        XGmLabel::Other(AString::try_from("Muy Importante").unwrap()),
                    ]),
                ]),
            ),
            (
                b"* 1 FETCH (UID 7 X-GM-LABELS ())\r\n".as_ref(),
                b"".as_ref(),
                fetch_response(vec![
                    MessageDataItem::Uid(NonZeroU32::new(7).unwrap()),
                    MessageDataItem::XGmLabels(vec![]),
                ]),
            ),
            (
                b"* 1 FETCH (X-GM-MSGID 18446744073709551615)\r\n".as_ref(),
                b"".as_ref(),
                fetch_response(vec![MessageDataItem::XGmMsgId(u64::MAX)]),
            ),
        ]);
    }

    #[test]
    fn test_kat_inverse_command_x_gm() {
        kat_inverse_command(&[(
            b"A FETCH 1 (X-GM-MSGID X-GM-THRID X-GM-LABELS)\r\n".as_ref(),
            b"".as_ref(),
            Command::new(
                "A",
                CommandBody::fetch(
                    1,
                    vec![
                        MessageDataItemName::XGmMsgId,
                        MessageDataItemName::XGmThrId,
                        MessageDataItemName::XGmLabels,
                    ],
                    false,
                )
                .unwrap(),
            )
            .unwrap(),
        )]);
    }

    #[test]
    fn test_encode_x_gm_label() {
        let tests = [
            (
                XGmLabel::System(Atom::try_from("Important").unwrap()),
                b"\\Important".as_ref(),
            ),
            (XGmLabel::Other(AString::try_from("Work").unwrap()), b"Work"),
            (
                XGmLabel::Other(AString::try_from("\\Inbox").unwrap()),
                b"\"\\\\Inbox\"",
            ),
        ];

        for test in tests {
            known_answer_test_encode(test);
        }
    }

    #[test]
    fn test_parse_x_gm_msg_att_rejects_overflow() {
        assert!(x_gm_msg_att(b"X-GM-MSGID 18446744073709551616)").is_err());
    }
}
