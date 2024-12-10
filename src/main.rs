use std::env;

use crate::dns::TYPE_A;
use crate::resolver::resolve;
mod dns;
mod resolver;

fn main() {
    let args: Vec<String> = env::args().collect();

    let domain_name = match &args.as_slice() {
        &[_, domain_name] => domain_name,
        _ => panic!("improper arguments"),
    };

    let result_ip_address = resolve(domain_name, TYPE_A);

    dbg!(result_ip_address);
}
