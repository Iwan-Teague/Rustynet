#![forbid(unsafe_code)]

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let command = args.get(1).map(String::as_str).unwrap_or("help");

    match command {
        "status" => println!("rustynet-cli scaffold: status=not-connected"),
        "login" => println!("rustynet-cli scaffold: login flow placeholder"),
        "exit-node" => println!("rustynet-cli scaffold: exit-node subcommand placeholder"),
        "netcheck" => println!("rustynet-cli scaffold: netcheck placeholder"),
        _ => {
            println!("rustynet-cli scaffold commands:");
            println!("  status");
            println!("  login");
            println!("  exit-node");
            println!("  netcheck");
        }
    }
}
