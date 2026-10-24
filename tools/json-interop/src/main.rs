// Development test only. The CLI never requires Rust or downloads dependencies.
use std::{env, fs};

fn main() {
    let args: Vec<String> = env::args().collect();
    let bytes = fs::read(&args[1]).expect("fixture must be readable");
    let parsed = serde_json::from_slice::<serde_json::Value>(&bytes);
    if args.get(2).map(String::as_str) == Some("--reject") {
        assert!(parsed.is_err(), "negative lone-surrogate fixture unexpectedly accepted");
    } else {
        assert!(parsed.is_ok(), "report/draft must parse as ordinary Unicode JSON: {:?}", parsed.err());
    }
}
