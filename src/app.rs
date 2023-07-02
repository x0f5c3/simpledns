use crate::dnssec;
use crate::server::Regex;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_with::{serde_as, DeserializeAs, SerializeAs};
use std::collections::HashMap;
use std::path::PathBuf;
use trust_dns_client::rr::Name;
use trust_dns_server::resolver::config::{NameServerConfigGroup, ResolverOpts};
use trust_dns_server::store::file::FileConfig;
use trust_dns_server::store::forwarder::ForwardConfig;
use trust_dns_server::store::recursor::RecursiveConfig;
use trust_dns_server::store::sqlite::SqliteConfig;

#[derive(Debug, Deserialize, Serialize)]
pub struct ServerConfig {
    /// The list of IPv4 addresses to listen on
    #[serde(default)]
    listen_addrs_ipv4: Vec<String>,
    /// This list of IPv6 addresses to listen on
    #[serde(default)]
    listen_addrs_ipv6: Vec<String>,
    /// Port on which to listen (associated to all IPs)
    listen_port: Option<u16>,
    /// Secure port to listen on
    tls_listen_port: Option<u16>,
    /// HTTPS port to listen on
    https_listen_port: Option<u16>,
    /// QUIC port to listen on
    quic_listen_port: Option<u16>,
    /// Timeout associated to a request before it is closed.
    tcp_request_timeout: Option<u64>,
    /// Level at which to log, default is INFO
    log_level: Option<String>,
    /// Base configuration directory, i.e. root path for zones
    directory: Option<String>,
    /// List of configurations for zones
    #[serde(default)]
    zones: HashMap<Regex, Name>,
    /// Certificate to associate to TLS connections (currently the same is used for HTTPS and TLS)
    tls_cert: Option<dnssec::TlsCertConfig>,
}

#[serde_as]
#[derive(Deserialize, Serialize, PartialEq, Eq, Debug)]
#[serde(tag = "type")]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum StoreConfig {
    /// File based configuration
    File(#[serde_as(as = "FileConfigDef")] FileConfig),
    /// Sqlite based configuration file
    Sqlite(#[serde_as(as = "SqliteConfigDef")] SqliteConfig),
    /// Forwarding Resolver
    Forward(#[serde_as(as = "ForwardConfigDef")] ForwardConfig),
    /// Recursive Resolver
    Recursor(#[serde_as(as = "RecursiveConfigDef")] RecursiveConfig),
}

#[serde_as]
#[derive(Deserialize, Serialize, PartialEq, Eq, Debug)]
#[serde(remote = "SqliteConfig")]
pub struct SqliteConfigDef {
    /// path to initial zone file
    pub zone_file_path: String,
    /// path to the sqlite journal file
    pub journal_file_path: String,
    /// Are updates allowed to this zone
    #[serde(default)]
    pub allow_update: bool,
}

impl SerializeAs<SqliteConfig> for SqliteConfigDef {
    fn serialize_as<S>(source: &SqliteConfig, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        SqliteConfigDef::serialize(source, serializer)
    }
}

impl<'de> DeserializeAs<'de, SqliteConfig> for SqliteConfigDef {
    fn deserialize_as<D>(deserializer: D) -> Result<SqliteConfig, D::Error>
    where
        D: Deserializer<'de>,
    {
        SqliteConfig::deserialize(deserializer)
    }
}

impl From<SqliteConfigDef> for SqliteConfig {
    fn from(value: SqliteConfigDef) -> Self {
        Self {
            allow_update: value.allow_update,
            zone_file_path: value.zone_file_path,
            journal_file_path: value.journal_file_path,
        }
    }
}

/// Configuration for file based recursive zones, serde adapter
#[serde_as]
#[derive(Deserialize, Serialize, PartialEq, Eq, Debug)]
#[serde(remote = "RecursiveConfig")]
pub struct RecursiveConfigDef {
    pub roots: PathBuf,
}

impl From<RecursiveConfigDef> for RecursiveConfig {
    fn from(value: RecursiveConfigDef) -> Self {
        Self { roots: value.roots }
    }
}

impl SerializeAs<RecursiveConfig> for RecursiveConfigDef {
    fn serialize_as<S>(source: &RecursiveConfig, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        RecursiveConfigDef::serialize(source, serializer)
    }
}

impl<'de> DeserializeAs<'de, RecursiveConfig> for RecursiveConfigDef {
    fn deserialize_as<D>(deserializer: D) -> Result<RecursiveConfig, D::Error>
    where
        D: Deserializer<'de>,
    {
        RecursiveConfig::deserialize(deserializer)
    }
}

/// Configuration for file based zones
#[serde_as]
#[derive(Deserialize, Serialize, PartialEq, Eq, Debug)]
#[serde(remote = "FileConfig")]
pub struct FileConfigDef {
    /// path to the zone file
    pub zone_file_path: String,
}

impl From<FileConfigDef> for FileConfig {
    fn from(value: FileConfigDef) -> Self {
        Self {
            zone_file_path: value.zone_file_path,
        }
    }
}

impl SerializeAs<FileConfig> for FileConfigDef {
    fn serialize_as<S>(source: &FileConfig, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        FileConfigDef::serialize(source, serializer)
    }
}

impl<'de> DeserializeAs<'de, FileConfig> for FileConfigDef {
    fn deserialize_as<D>(deserializer: D) -> Result<FileConfig, D::Error>
    where
        D: Deserializer<'de>,
    {
        FileConfig::deserialize(deserializer)
    }
}

/// Configuration for file based zones
#[serde_as]
#[derive(Clone, Deserialize, Serialize, PartialEq, Eq, Debug)]
#[serde(remote = "ForwardConfig")]
pub struct ForwardConfigDef {
    /// upstream name_server configurations
    pub name_servers: NameServerConfigGroup,
    /// Resolver options
    pub options: Option<ResolverOpts>,
}

impl From<ForwardConfigDef> for ForwardConfig {
    fn from(value: ForwardConfigDef) -> Self {
        Self {
            name_servers: value.name_servers,
            options: value.options,
        }
    }
}

impl SerializeAs<ForwardConfig> for ForwardConfigDef {
    fn serialize_as<S>(source: &ForwardConfig, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        ForwardConfigDef::serialize(source, serializer)
    }
}

impl<'de> DeserializeAs<'de, ForwardConfig> for ForwardConfigDef {
    fn deserialize_as<D>(deserializer: D) -> Result<ForwardConfig, D::Error>
    where
        D: Deserializer<'de>,
    {
        ForwardConfig::deserialize(deserializer)
    }
}
