use std::env;

use crate::dns::TYPE_A;
use crate::resolver::resolve;
mod dns;
mod error;
mod resolver;

pub use self::error::{Error, Result};

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();

    let domain_name = match &args.as_slice() {
        &[_, domain_name] => domain_name,
        _ => panic!("improper arguments"),
    };

    let result_ip_address = resolve(domain_name, TYPE_A)?;

    println!("Resolved IP address: {}", result_ip_address);

    Ok(())
}
