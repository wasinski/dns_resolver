use std::env;

use crate::dns::TYPE_A;
use crate::resolver::send_query;
mod dns;
mod resolver;

fn main() {
    let args: Vec<String> = env::args().collect();

    let domain_name = match &args.as_slice() {
        &[_, domain_name] => domain_name,
        _ => panic!("improper arguments"),
    };

    let result_ip_address = send_query("8.8.8.8", domain_name, TYPE_A);

    dbg!(result_ip_address);
}
