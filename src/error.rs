use std::{
    error::Error,
    fmt::{Display, Formatter},
};

use crate::PairKey;

/// XFCC header parsing error
#[derive(Debug, PartialEq)]
pub enum XfccError<'a> {
    /// Used by [`element_list`](crate::element_list) when there is unconsumed data at the
    /// end of an XFCC header
    TrailingSequence(&'a [u8]),
    /// Used by [`element_list`](crate::element_list) when more than one value is given for a
    /// key that accepts only one value
    DuplicatePairKey(PairKey),
    /// Represents an underlying parsing error
    ParsingError(nom::Err<nom::error::Error<&'a [u8]>>),
}

impl<'a> Display for XfccError<'a> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TrailingSequence(seq) => write!(f, "Trailing sequence {:?}", seq)?,
            Self::DuplicatePairKey(key) => write!(f, "Duplicate pair key {key}")?,
            Self::ParsingError(nom_err) => write!(f, "Parsing error {nom_err}")?,
        }
        Ok(())
    }
}

impl<'a> Error for XfccError<'a> {}

impl<'a> From<nom::Err<nom::error::Error<&'a [u8]>>> for XfccError<'a> {
    fn from(value: nom::Err<nom::error::Error<&'a [u8]>>) -> Self {
        Self::ParsingError(value)
    }
}
