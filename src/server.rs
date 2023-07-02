use crate::dnssec;
use anyhow::Context;
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use std::collections::{BTreeMap, HashMap};
use std::fmt::Display;
use std::hash::Hasher;
use std::str::FromStr;
use trust_dns_server::proto::rr::Name;

#[derive(Debug, Deserialize, Serialize)]
pub enum Matcher {
    Literal(Name),
    Regex(Regex),
}

pub struct Route {
    regex: Option<RegexConfig>,
    literal: Option<String>,
}

pub struct RegexConfig {
    enabled: bool,
    matcher: String,
}

// pub trait Matcher {
//     type Error;
//     fn is_match(s: &str) -> Result<(), Self::Error>;
// }

#[derive(Debug, Clone)]
pub struct Regex {
    orig: String,
    inner: regex::Regex,
}

impl Serialize for Regex {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.orig)
    }
}

impl<'de> Deserialize<'de> for Regex {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let orig: &str = Deserialize::deserialize(deserializer)?;
        Self::try_from(orig).map_err(de::Error::custom)
    }
}

impl PartialEq<Self> for Regex {
    fn eq(&self, other: &Self) -> bool {
        self.orig == other.orig
    }
}

impl Eq for Regex {}

impl std::hash::Hash for Regex {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.inner.as_str().hash(state)
    }
}

impl From<Regex> for String {
    fn from(value: Regex) -> Self {
        value.orig
    }
}

impl FromStr for Regex {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::try_from(s)
    }
}

impl AsRef<str> for Regex {
    fn as_ref(&self) -> &str {
        &self.orig
    }
}

impl TryFrom<&str> for Regex {
    type Error = anyhow::Error;
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let inner = regex::Regex::new(value).context("Cannot deserialize regex")?;
        Ok(Self {
            orig: value.to_string(),
            inner,
        })
    }
}

pub struct Server {
    routes: BTreeMap<Regex, Name>,
    proto: trust_dns_server::server::Protocol,
}
