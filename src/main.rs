fn main() {
    let version = 0;

    match version {
        0 => {
            arpdump::v0::run();
        }
        _ => {
            println!("Invalid version");
        }
    }
}
