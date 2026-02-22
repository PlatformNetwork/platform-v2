use sp_core::{sr25519, Pair};
use std::env;

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        print_usage();
        return;
    }

    match args[1].as_str() {
        "hotkey-from-mnemonic" => {
            if args.len() < 3 {
                eprintln!("Usage: utils hotkey-from-mnemonic <mnemonic>");
                std::process::exit(1);
            }
            let mnemonic = &args[2];
            let (pair, _) = sr25519::Pair::from_phrase(mnemonic, None).expect("Invalid mnemonic");
            println!("{}", hex::encode(pair.public().0));
        }
        "sign" => {
            if args.len() < 4 {
                eprintln!("Usage: utils sign <mnemonic> <message>");
                std::process::exit(1);
            }
            let mnemonic = &args[2];
            let message = &args[3];
            let (pair, _) = sr25519::Pair::from_phrase(mnemonic, None).expect("Invalid mnemonic");
            let signature = pair.sign(message.as_bytes());
            println!("{}", hex::encode(signature.0));
        }
        "verify" => {
            if args.len() < 5 {
                eprintln!("Usage: utils verify <hotkey_hex> <message> <signature_hex>");
                std::process::exit(1);
            }
            let hotkey_hex = &args[2];
            let message = &args[3];
            let sig_hex = &args[4];

            let hotkey_bytes = hex::decode(hotkey_hex).expect("Invalid hotkey hex");
            let sig_bytes = hex::decode(sig_hex).expect("Invalid signature hex");

            let mut hotkey_arr = [0u8; 32];
            let mut sig_arr = [0u8; 64];
            hotkey_arr.copy_from_slice(&hotkey_bytes);
            sig_arr.copy_from_slice(&sig_bytes);

            let public = sr25519::Public::from_raw(hotkey_arr);
            let signature = sr25519::Signature::from_raw(sig_arr);

            let valid = sr25519::Pair::verify(&signature, message.as_bytes(), &public);
            println!("{}", valid);
        }
        "from-seed" => {
            if args.len() < 3 {
                eprintln!("Usage: utils from-seed <seed_hex>");
                std::process::exit(1);
            }
            let seed_hex = &args[2];
            let bytes = hex::decode(seed_hex).expect("Invalid hex");
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            let pair = sr25519::Pair::from_seed(&arr);
            println!("{}", hex::encode(pair.public().0));
        }
        _ => {
            print_usage();
        }
    }
}

fn print_usage() {
    eprintln!("Platform Utilities");
    eprintln!();
    eprintln!("Commands:");
    eprintln!("  hotkey-from-mnemonic <mnemonic>  - Get hotkey from BIP39 mnemonic");
    eprintln!("  sign <mnemonic> <message>        - Sign a message with mnemonic");
    eprintln!("  verify <hotkey> <message> <sig>  - Verify a signature");
    eprintln!("  from-seed <seed_hex>             - Get hotkey from seed hex");
}
