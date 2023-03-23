pub mod error;

use std::{
    borrow::{Borrow, Cow},
    str::{FromStr, Utf8Error},
    string::FromUtf8Error,
};

pub use error::XfccError;
use nom::{
    branch::alt,
    bytes::complete::{escaped_transform, is_not, tag, take, take_till},
    character::complete::char,
    combinator::{eof, map, map_res, value},
    multi::{separated_list0, separated_list1},
    sequence::{delimited, tuple},
    AsChar, IResult,
};
use strum::EnumString;

const DOUBLE_QUOTE: u8 = b'"';
const SLASH: u8 = b'\\';
const COMMA: u8 = b',';
const SEMICOLON: u8 = b';';
const EQUAL: u8 = b'=';

/// Variants of pair keys in XFCC elements
#[derive(Debug, PartialEq, Eq, EnumString, strum::Display)]
pub enum PairKey {
    /// The Subject Alternative Name (URI type) of the current proxy's certificate
    By,
    /// The SHA 256 digest of the current client certificate
    Hash,
    /// The entire client certificate in URL encoded PEM format
    Cert,
    /// The entire client certificate chain (including the leaf certificate) in URL encoded PEM format
    Chain,
    /// The Subject field of the current client certificate
    Subject,
    /// The URI type Subject Alternative Name field of the current client certificate
    #[strum(serialize = "URI")]
    Uri,
    /// The DNS type Subject Alternative Name field of the current client certificate
    #[strum(serialize = "DNS")]
    Dns,
}

/// A list of key-value pairs representing a raw XFCC element
pub type ElementRaw<'a> = Vec<(PairKey, Cow<'a, str>)>;

/// An XFCC element
#[derive(Debug, PartialEq, Eq, Default)]
pub struct Element<'a> {
    pub by: Vec<Cow<'a, str>>,
    pub hash: Option<Cow<'a, str>>,
    pub cert: Option<Cow<'a, str>>,
    pub chain: Option<Cow<'a, str>>,
    pub subject: Option<Cow<'a, str>>,
    pub uri: Vec<Cow<'a, str>>,
    pub dns: Vec<Cow<'a, str>>,
}

impl<'a> TryFrom<ElementRaw<'a>> for Element<'a> {
    type Error = XfccError<'a>;

    fn try_from(element_raw: ElementRaw<'a>) -> Result<Self, Self::Error> {
        let mut element = Self::default();
        for (key, value) in element_raw {
            if value.is_empty() {
                continue;
            }
            macro_rules! error_if_duplicate {
                ($key_type:expr, $key_field:ident) => {
                    if element.$key_field.is_some() {
                        return Err(XfccError::DuplicatePairKey($key_type));
                    } else {
                        element.$key_field = Some(value);
                    }
                };
            }
            match key {
                PairKey::By => element.by.push(value),
                PairKey::Hash => error_if_duplicate!(PairKey::Hash, hash),
                PairKey::Cert => error_if_duplicate!(PairKey::Cert, cert),
                PairKey::Chain => error_if_duplicate!(PairKey::Chain, chain),
                PairKey::Subject => error_if_duplicate!(PairKey::Subject, subject),
                PairKey::Uri => element.uri.push(value),
                PairKey::Dns => element.dns.push(value),
            }
        }
        Ok(element)
    }
}

fn to_cow_str(s: &[u8]) -> Result<Cow<str>, Utf8Error> {
    std::str::from_utf8(s).map(Cow::from)
}

fn to_owned_cow_str(s: Vec<u8>) -> Result<Cow<'static, str>, FromUtf8Error> {
    String::from_utf8(s).map(Cow::from)
}

fn empty_quoted_value(s: &[u8]) -> IResult<&[u8], Cow<str>> {
    map(value("", tag([DOUBLE_QUOTE, DOUBLE_QUOTE])), Cow::from)(s)
}

fn escaped_value(s: &[u8]) -> IResult<&[u8], Cow<str>> {
    map_res(
        escaped_transform(
            is_not(&[DOUBLE_QUOTE, SLASH][..]),
            SLASH.as_char(),
            take(1u8),
        ),
        to_owned_cow_str,
    )(s)
}

fn quoted_value(s: &[u8]) -> IResult<&[u8], Cow<str>> {
    alt((
        empty_quoted_value,
        delimited(
            char(DOUBLE_QUOTE.as_char()),
            escaped_value,
            char(DOUBLE_QUOTE.as_char()),
        ),
    ))(s)
}

fn unquoted_value(s: &[u8]) -> IResult<&[u8], Cow<str>> {
    map_res(
        alt((
            take_till(|c| c == COMMA || c == SEMICOLON || c == EQUAL),
            eof,
        )),
        to_cow_str,
    )(s)
}

fn pair_key(s: &[u8]) -> IResult<&[u8], PairKey> {
    map_res(
        alt((
            tag("By"),
            tag("Hash"),
            tag("Cert"),
            tag("Chain"),
            tag("Subject"),
            tag("URI"),
            tag("DNS"),
        )),
        |name| {
            to_cow_str(name).map(|name| match PairKey::from_str(name.borrow()) {
                Ok(key) => key,
                Err(_) => unreachable!("Failed to parse PairKey while nom succeeded"),
            })
        },
    )(s)
}

fn pair(s: &[u8]) -> IResult<&[u8], (PairKey, Cow<str>)> {
    let (s, (key, _, value)) =
        tuple((pair_key, char('='), alt((quoted_value, unquoted_value))))(s)?;
    Ok((s, (key, value)))
}

fn element(s: &[u8]) -> IResult<&[u8], ElementRaw> {
    separated_list1(char(';'), pair)(s)
}

/// Parses an XFCC header to a list of raw XFCC elements, each consists of a list of key-value pairs
///
/// # Arguments
///
/// * `s` - An XFCC header
///
/// # Examples
///
/// ```
/// use std::borrow::Cow;
/// use xfcc_parser::PairKey;
///
/// let input = br#"By=http://frontend.lyft.com;Subject="/C=US/ST=CA/L=San Francisco/OU=Lyft/CN=Test Client";URI=http://testclient.lyft.com"#;
/// let (trailing, elements) = xfcc_parser::element_raw_list(input).unwrap();
///
/// assert!(trailing.is_empty());
/// assert_eq!(elements[0], vec![
///     (PairKey::By, Cow::from("http://frontend.lyft.com")),
///     (PairKey::Subject, Cow::from("/C=US/ST=CA/L=San Francisco/OU=Lyft/CN=Test Client")),
///     (PairKey::Uri, Cow::from("http://testclient.lyft.com")),
/// ]);
/// ```
pub fn element_raw_list(s: &[u8]) -> IResult<&[u8], Vec<ElementRaw>> {
    separated_list0(char(','), element)(s)
}

/// Parses an XFCC header to a list of XFCC elements
///
/// # Arguments
///
/// * `s` - An XFCC header
///
/// # Examples
///
/// ```
/// use std::borrow::Cow;
/// use xfcc_parser::Element;
///
/// let input = br#"By=http://frontend.lyft.com;Subject="/C=US/ST=CA/L=San Francisco/OU=Lyft/CN=Test Client";URI=http://testclient.lyft.com"#;
/// let elements = xfcc_parser::element_list(input).unwrap();
///
/// assert_eq!(
///     elements[0],
///     Element {
///         by: vec![Cow::from("http://frontend.lyft.com")],
///         hash: None,
///         cert: None,
///         chain: None,
///         subject: Some(Cow::from("/C=US/ST=CA/L=San Francisco/OU=Lyft/CN=Test Client")),
///         uri: vec![Cow::from("http://testclient.lyft.com")],
///         dns: vec![],
///     }
/// );
/// ```
pub fn element_list(s: &[u8]) -> Result<Vec<Element>, XfccError> {
    let (trailing, raw_list) = element_raw_list(s)?;

    if !trailing.is_empty() {
        return Err(XfccError::TrailingSequence(trailing));
    }

    let mut elements = vec![];
    raw_list
        .into_iter()
        .try_for_each(|element_raw| -> Result<(), XfccError> {
            elements.push(Element::try_from(element_raw)?);
            Ok(())
        })?;

    Ok(elements)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_escaped_value_test() {
        let input = br#"hello, \"world\"!"#;
        assert_eq!(
            escaped_value(input),
            Ok((&[][..], Cow::from(r#"hello, "world"!"#)))
        );
    }

    #[test]
    fn unnecessarily_escaped_value_test() {
        let input = br#"\h\e\l\l\o, \"world\"!"#;
        assert_eq!(
            escaped_value(input),
            Ok((&[][..], Cow::from(r#"hello, "world"!"#)))
        );
    }

    #[test]
    fn utf8_escaped_value_test() {
        let input: Vec<u8> = "こんにちは"
            .bytes()
            .flat_map(|b| [b'\\', b].into_iter())
            .collect();
        assert_eq!(
            escaped_value(&input),
            Ok((&[][..], Cow::from("こんにちは")))
        );
    }

    #[test]
    fn invalid_utf8_escaped_value_test() {
        let mut input: Vec<u8> = "こんにちは".bytes().collect();
        input.pop().unwrap();
        assert_eq!(
            escaped_value(&input),
            Err(nom::Err::Error(nom::error::Error {
                input: &input[..],
                code: nom::error::ErrorKind::MapRes
            }))
        );
    }

    #[test]
    fn basic_quoted_value_test() {
        let input = br#""hello, \"world\"!""#;
        assert_eq!(
            quoted_value(input),
            Ok((&[][..], Cow::from(r#"hello, "world"!"#)))
        );
    }

    #[test]
    fn empty_quoted_value_test() {
        let input = br#""""#;
        assert_eq!(empty_quoted_value(input), Ok((&[][..], Cow::from(""))));
        assert_eq!(quoted_value(input), Ok((&[][..], Cow::from(""))));
    }

    #[test]
    fn basic_unquoted_value_test() {
        let input = b"hello! world!;";
        let parsed = unquoted_value(input).unwrap();
        assert_eq!(parsed, (&[SEMICOLON][..], Cow::from("hello! world!")));
        assert!(matches!(parsed.1, Cow::Borrowed(_)));

        let input = b"hello! world!";
        let parsed = unquoted_value(input).unwrap();
        assert_eq!(parsed, (&[][..], Cow::from("hello! world!")));
        assert!(matches!(parsed.1, Cow::Borrowed(_)));
    }

    #[test]
    fn must_be_quoted_in_unquoted_value_test() {
        let input = b"hello, world!;";
        assert_eq!(
            unquoted_value(input),
            Ok((&b", world!;"[..], Cow::from("hello")))
        );
    }

    #[test]
    fn basic_pair_key_test() {
        let input = b"Chain";
        assert_eq!(pair_key(input), Ok((&[][..], PairKey::Chain)));
    }

    #[test]
    fn invalid_pair_key_test() {
        let input = b"Example";
        assert_eq!(
            pair_key(input),
            Err(nom::Err::Error(nom::error::Error {
                input: &input[..],
                code: nom::error::ErrorKind::Tag
            }))
        );
    }

    #[test]
    fn basic_pair_test() {
        let input = br#"Chain=hello! world!;"#;
        let parsed = pair(input).unwrap();
        assert_eq!(
            parsed,
            (&b";"[..], (PairKey::Chain, Cow::from("hello! world!")))
        );
        assert!(matches!(parsed.1 .1, Cow::Borrowed(_)));

        let input = br#"Chain=hello! world!"#;
        let parsed = pair(input).unwrap();
        assert_eq!(
            parsed,
            (&[][..], (PairKey::Chain, Cow::from("hello! world!")))
        );
        assert!(matches!(parsed.1 .1, Cow::Borrowed(_)));
    }

    #[test]
    fn quoted_value_pair_test() {
        let input = br#"Chain="hello! world!";"#;
        let parsed = pair(input).unwrap();
        assert_eq!(
            parsed,
            (&b";"[..], (PairKey::Chain, Cow::from("hello! world!")))
        );
        assert!(matches!(parsed.1 .1, Cow::Owned(_)));

        let input = br#"Chain="hello! world!""#;
        let parsed = pair(input).unwrap();
        assert_eq!(
            parsed,
            (&[][..], (PairKey::Chain, Cow::from("hello! world!")))
        );
        assert!(matches!(parsed.1 .1, Cow::Owned(_)));
    }

    #[test]
    fn basic_element_test() {
        let input = br#"By=http://frontend.lyft.com;Hash=468ed33be74eee6556d90c0149c1309e9ba61d6425303443c0748a02dd8de688;Subject="/C=US/ST=CA/L=San Francisco/OU=Lyft/CN=Test Client";URI=http://testclient.lyft.com"#;
        assert_eq!(
            element(input),
            Ok((
                &[][..],
                (vec![
                    (PairKey::By, Cow::from("http://frontend.lyft.com")),
                    (
                        PairKey::Hash,
                        Cow::from(
                            "468ed33be74eee6556d90c0149c1309e9ba61d6425303443c0748a02dd8de688"
                        )
                    ),
                    (
                        PairKey::Subject,
                        Cow::from("/C=US/ST=CA/L=San Francisco/OU=Lyft/CN=Test Client")
                    ),
                    (PairKey::Uri, Cow::from("http://testclient.lyft.com"))
                ])
            ))
        );
    }

    #[test]
    fn empty_value_in_element_test() {
        let input = br#"By=;By=http://frontend.lyft.com;Hash=468ed33be74eee6556d90c0149c1309e9ba61d6425303443c0748a02dd8de688;Subject="/C=US/ST=CA/L=San Francisco/OU=Lyft/CN=Test Client";URI=http://testclient.lyft.com"#;
        assert_eq!(
            element(input),
            Ok((
                &[][..],
                (vec![
                    (PairKey::By, Cow::from("")),
                    (PairKey::By, Cow::from("http://frontend.lyft.com")),
                    (
                        PairKey::Hash,
                        Cow::from(
                            "468ed33be74eee6556d90c0149c1309e9ba61d6425303443c0748a02dd8de688"
                        )
                    ),
                    (
                        PairKey::Subject,
                        Cow::from("/C=US/ST=CA/L=San Francisco/OU=Lyft/CN=Test Client")
                    ),
                    (PairKey::Uri, Cow::from("http://testclient.lyft.com"))
                ])
            ))
        );
    }

    #[test]
    fn basic_element_raw_list_test() {
        let input = br#"By=http://frontend.lyft.com;Hash=468ed33be74eee6556d90c0149c1309e9ba61d6425303443c0748a02dd8de688;Subject="/C=US/ST=CA/L=San Francisco/OU=Lyft/CN=Test Client";URI=http://testclient.lyft.com,By=http://example.com;By=http://instance.com"#;
        assert_eq!(
            element_raw_list(input),
            Ok((
                &[][..],
                vec![
                    vec![
                        (PairKey::By, Cow::from("http://frontend.lyft.com")),
                        (
                            PairKey::Hash,
                            Cow::from(
                                "468ed33be74eee6556d90c0149c1309e9ba61d6425303443c0748a02dd8de688"
                            )
                        ),
                        (
                            PairKey::Subject,
                            Cow::from("/C=US/ST=CA/L=San Francisco/OU=Lyft/CN=Test Client")
                        ),
                        (PairKey::Uri, Cow::from("http://testclient.lyft.com"))
                    ],
                    vec![
                        (PairKey::By, Cow::from("http://example.com")),
                        (PairKey::By, Cow::from("http://instance.com"))
                    ]
                ]
            ))
        );

        // https://github.com/alecholmes/xfccparser/blob/master/parser_test.go
        let input = br#"Hash=hash;Cert="-----BEGIN%20CERTIFICATE-----%0cert%0A-----END%20CERTIFICATE-----%0A";Subject="CN=hello,OU=hello,O=Acme\, Inc.";URI=;DNS=hello.west.example.com;DNS=hello.east.example.com,By=spiffe://mesh.example.com/ns/hellons/sa/hellosa;Hash=again;Subject="";URI=spiffe://mesh.example.com/ns/otherns/sa/othersa"#;
        assert_eq!(
            element_raw_list(input),
            Ok((
                &[][..],
                vec![
                    vec![
                        (PairKey::Hash, Cow::from("hash")),
                        (
                            PairKey::Cert,
                            Cow::from("-----BEGIN%20CERTIFICATE-----%0cert%0A-----END%20CERTIFICATE-----%0A")
                        ),
                        (PairKey::Subject, Cow::from("CN=hello,OU=hello,O=Acme, Inc.")),
                        (PairKey::Uri, Cow::from("")),
                        (PairKey::Dns, Cow::from("hello.west.example.com")),
                        (PairKey::Dns, Cow::from("hello.east.example.com"))
                    ],
                    vec![
                        (
                            PairKey::By,
                            Cow::from("spiffe://mesh.example.com/ns/hellons/sa/hellosa")
                        ),
                        (PairKey::Hash, Cow::from("again")),
                        (PairKey::Subject, Cow::from("")),
                        (
                            PairKey::Uri,
                            Cow::from("spiffe://mesh.example.com/ns/otherns/sa/othersa")
                        )
                    ]
                ]
            ))
        );
    }

    #[test]
    fn basic_element_list_test() {
        let input = br#"By=http://frontend.lyft.com;Hash=468ed33be74eee6556d90c0149c1309e9ba61d6425303443c0748a02dd8de688;Subject="/C=US/ST=CA/L=San Francisco/OU=Lyft/CN=Test Client";URI=http://testclient.lyft.com,By=http://example.com;By=http://instance.com"#;
        let certificates = element_list(input).unwrap();
        assert_eq!(certificates.len(), 2);
        assert_eq!(
            certificates[0],
            Element {
                by: vec![Cow::from("http://frontend.lyft.com")],
                hash: Some(Cow::from(
                    "468ed33be74eee6556d90c0149c1309e9ba61d6425303443c0748a02dd8de688"
                )),
                cert: None,
                chain: None,
                subject: Some(Cow::from(
                    "/C=US/ST=CA/L=San Francisco/OU=Lyft/CN=Test Client"
                )),
                uri: vec![Cow::from("http://testclient.lyft.com")],
                dns: vec![],
            }
        );
        assert_eq!(
            certificates[1],
            Element {
                by: vec![
                    Cow::from("http://example.com"),
                    Cow::from("http://instance.com")
                ],
                hash: None,
                cert: None,
                chain: None,
                subject: None,
                uri: vec![],
                dns: vec![],
            }
        );
    }

    #[test]
    fn empty_subject_element_list_test() {
        let input = br#"By=http://example.com;Subject="""#;
        let certificates = element_list(input).unwrap();
        assert_eq!(certificates.len(), 1);
        assert_eq!(
            certificates[0],
            Element {
                by: vec![Cow::from("http://example.com"),],
                hash: None,
                cert: None,
                chain: None,
                subject: None,
                uri: vec![],
                dns: vec![],
            }
        );
    }

    #[test]
    fn duplicate_pair_key_test() {
        let input = br#"By=http://example.com;Hash=hash1;Hash=hash2"#;
        assert_eq!(
            element_raw_list(input),
            Ok((
                &[][..],
                vec![vec![
                    (PairKey::By, Cow::from("http://example.com")),
                    (PairKey::Hash, Cow::from("hash1")),
                    (PairKey::Hash, Cow::from("hash2")),
                ]]
            ))
        );
        assert_eq!(
            element_list(input),
            Err(XfccError::DuplicatePairKey(PairKey::Hash))
        );
    }

    #[test]
    fn trailing_characters_test() {
        let input = br#"By=http://example.com;Hash=hash,URI"#;
        assert_eq!(
            element_raw_list(input),
            Ok((
                &b",URI"[..],
                vec![vec![
                    (PairKey::By, Cow::from("http://example.com")),
                    (PairKey::Hash, Cow::from("hash")),
                ]]
            ))
        );
        assert_eq!(
            element_list(input),
            Err(XfccError::TrailingSequence(&b",URI"[..]))
        );
    }
}
