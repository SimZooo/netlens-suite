use clap::Parser;

#[derive(Parser, Debug)]
#[command(version, long_about = None)]
struct Args {
    #[arg()]
    file: String
}

fn main() {
    let args = Args::parse();
    let file = args.file;
    let json = std::fs::read_to_string(file);
    if let Ok(json) = json {
        println!("{}", json);
    }
}