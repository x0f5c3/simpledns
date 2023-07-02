use build_info::build_info;

pub(crate) use trust_dns_server::{authority, proto, recursor, resolver, store};
mod app;
mod dnssec;
pub mod server;

build_info!(pub fn build);

fn main() {
    println!("Hello, world!");
}
