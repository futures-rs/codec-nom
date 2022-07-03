use bytes::{Bytes, BytesMut};
use futures_framed::Decoder;
use nom::{IResult, Needed};
use std::marker::PhantomData;

pub struct NomCodec<Parsed, Parser>
where
    for<'a> Parser: NomParser<'a>,
{
    decode_need_message_bytes: usize,
    _parsed: PhantomData<Parsed>,
    parser: Parser,
}

pub trait NomParser<'a> {
    type Parsed: 'a + Sized;

    fn parse(&self, buf: &'a [u8]) -> IResult<&'a [u8], Self::Parsed>;
}

impl<Parsed, Parser> NomCodec<Parsed, Parser>
where
    for<'a> Parser: NomParser<'a>,
{
    pub fn new(parser: Parser) -> Self {
        assert!(std::mem::size_of::<Parser::Parsed>() == std::mem::size_of::<Parsed>());

        Self {
            decode_need_message_bytes: 0,
            _parsed: Default::default(),
            parser,
        }
    }
}

impl<Parsed, Parser> Decoder for NomCodec<Parsed, Parser>
where
    Parsed: 'static + Sized,
    for<'a> Parser: NomParser<'a>,
{
    type Item = NomInput<Parsed>;

    type Error = anyhow::Error;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if buf.is_empty() || self.decode_need_message_bytes > buf.len() {
            return Ok(None);
        }

        let (response, rsp_len) = match self.parser.parse(buf) {
            Ok((remaining, response)) => {
                // This SHOULD be acceptable/safe: BytesMut storage memory is
                // allocated on the heap and should not move. It will not be
                // freed as long as we keep a reference alive, which we do
                // by retaining a reference to the split buffer, below.
                let response = unsafe {
                    let b = ::core::ptr::read(&response as *const Parser::Parsed as *const Parsed);

                    ::core::mem::forget(response);

                    b
                };
                (response, buf.len() - remaining.len())
            }
            Err(nom::Err::Incomplete(Needed::Size(min))) => {
                self.decode_need_message_bytes = min.get();
                return Ok(None);
            }
            Err(nom::Err::Incomplete(_)) => {
                return Ok(None);
            }
            Err(nom::Err::Error(nom::error::Error { code, .. }))
            | Err(nom::Err::Failure(nom::error::Error { code, .. })) => {
                return Err(anyhow::format_err!(
                    "{:?} during parsing of {:?}",
                    code,
                    buf
                ));
            }
        };
        let raw = buf.split_to(rsp_len).freeze();

        self.decode_need_message_bytes = 0;

        Ok(Some(Self::Item {
            raw,
            parsed: response,
        }))

        // Err(anyhow::format_err!("not implement"))
    }
}

#[derive(Debug)]
pub struct NomInput<Parsed>
where
    Parsed: 'static + Sized,
{
    #[allow(dead_code)] // Contains data that `response` borrows
    raw: Bytes,
    // This reference is really scoped to the lifetime of the `raw`
    // member, but unfortunately Rust does not allow that yet. It
    // is transmuted to `'static` by the `Decoder`, instead, and
    // references returned to callers of `ResponseData` are limited
    // to the lifetime of the `ResponseData` struct.
    //
    // `raw` is never mutated during the lifetime of `ResponseData`,
    // and `Response` does not not implement any specific drop glue.
    pub parsed: Parsed,
}

#[allow(dead_code)]
#[cfg(test)]
mod tests {

    use super::*;

    use nom::{
        branch::alt,
        bytes::streaming::{tag, tag_no_case},
        combinator::{map, opt},
        sequence::tuple,
        IResult,
    };

    use std::borrow::Cow;

    use nom::{bytes::streaming::take_while, combinator::map_res};

    use nom::character::streaming::digit1;

    use std::str::from_utf8;

    #[derive(Debug)]
    pub enum Response<'a> {
        Ok(Option<Cow<'a, str>>),
        Err(Cow<'a, str>),
        List((u32, u32)),
        ListUid((u32, Cow<'a, str>)),
        Body(Cow<'a, str>),
        Done,
    }

    pub fn text(i: &[u8]) -> IResult<&[u8], &str> {
        map_res(take_while(is_text_char), from_utf8)(i)
    }

    pub fn is_text_char(c: u8) -> bool {
        c != b'\r' && c != b'\n'
    }

    pub fn is_char(c: u8) -> bool {
        matches!(c, 0x01..=0x7F)
    }

    use std::str::FromStr;

    pub fn number(i: &[u8]) -> IResult<&[u8], u32> {
        let (i, bytes) = digit1(i)?;
        match from_utf8(bytes).ok().and_then(|s| u32::from_str(s).ok()) {
            Some(v) => Ok((i, v)),
            None => Err(nom::Err::Error(nom::error::make_error(
                i,
                nom::error::ErrorKind::MapRes,
            ))),
        }
    }

    // -ERR ... CRLF
    pub fn parse_error_status(i: &[u8]) -> IResult<&[u8], Response<'_>> {
        map(
            tuple((tag_no_case("-ERR "), text, tag("\r\n"))),
            |(_, msg, _)| Response::Err(Cow::Borrowed(msg)),
        )(i)
    }

    // +OK ... CRLF
    pub fn parse_ok_status(i: &[u8]) -> IResult<&[u8], Response<'_>> {
        map(
            tuple((tag_no_case("+OK"), opt(tag(" ")), opt(text), tag("\r\n"))),
            |(_, _, msg, _)| {
                if msg.is_some() && msg.unwrap().len() > 0 {
                    Response::Ok(msg.map(Cow::Borrowed))
                } else {
                    Response::Ok(None)
                }
            },
        )(i)
    }
    // +OK 3 23430CRLF
    pub fn parse_ok_list(i: &[u8]) -> IResult<&[u8], Response<'_>> {
        map(
            tuple((
                tag_no_case("+OK"),
                opt(tag(" ")),
                number,
                tag(" "),
                number,
                tag("\r\n"),
            )),
            |(_, _, left, _, right, _)| Response::List((left, right)),
        )(i)
    }

    pub fn parse_list_line(i: &[u8]) -> IResult<&[u8], Response<'_>> {
        map(
            tuple((number, tag(" "), number, tag("\r\n"))),
            |(index, _, size, _)| Response::List((index, size)),
        )(i)
    }

    pub fn parse_uidl_line(i: &[u8]) -> IResult<&[u8], Response<'_>> {
        map(
            tuple((number, tag(" "), text, tag("\r\n"))),
            |(index, _, uid, _)| Response::ListUid((index, uid.into())),
        )(i)
    }

    pub fn parse_list_done(i: &[u8]) -> IResult<&[u8], Response<'_>> {
        map(tuple((tag("."), tag("\r\n"))), |(_, _)| Response::Done)(i)
    }

    pub fn parse_retr_body(i: &[u8]) -> IResult<&[u8], Response<'_>> {
        map(tuple((text, tag("\r\n"))), |(body, _)| {
            Response::Body(Cow::Borrowed(body))
        })(i)
    }

    pub fn parse_response(i: &[u8]) -> IResult<&[u8], Response<'_>> {
        alt((
            parse_error_status,
            parse_ok_list,
            parse_ok_status,
            parse_list_line,
            parse_uidl_line,
            parse_list_done,
            parse_retr_body,
        ))(i)
    }

    struct Parser;

    impl<'a> NomParser<'a> for Parser {
        type Parsed = Response<'a>;

        fn parse(&self, buf: &'a [u8]) -> IResult<&'a [u8], Self::Parsed> {
            alt((
                parse_error_status,
                parse_ok_list,
                parse_ok_status,
                parse_list_line,
                parse_uidl_line,
                parse_list_done,
                parse_retr_body,
            ))(buf)
        }
    }

    #[test]
    fn test_nome_parser() -> Result<(), anyhow::Error> {
        let mut codec = NomCodec {
            parser: Parser {},
            decode_need_message_bytes: 0,
            _parsed: PhantomData::<Response<'static>>,
        };

        let mut buf = BytesMut::from(&b"-ERR no such message\r\n"[..]);

        codec.decode(&mut buf)?;

        Ok(())
    }
}
