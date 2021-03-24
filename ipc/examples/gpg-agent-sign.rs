/// Signs data using the openpgp crate and secrets in gpg-agent.

use std::io;

use clap;
use sequoia_openpgp as openpgp;
use sequoia_ipc as ipc;

use crate::openpgp::parse::Parse;
use crate::openpgp::serialize::stream::{Armorer, Message, LiteralWriter, Signer};
use crate::openpgp::policy::StandardPolicy as P;
use crate::ipc::gnupg::{Context, KeyPair};

fn main() {
    let p = &P::new();

    let matches = clap::App::new("gpg-agent-sign")
        .version(env!("CARGO_PKG_VERSION"))
        .about("Connects to gpg-agent and creates a dummy signature.")
        .arg(clap::Arg::with_name("homedir").value_name("PATH")
             .long("homedir")
             .help("Use this GnuPG home directory, default: $GNUPGHOME"))
        .arg(clap::Arg::with_name("cert").value_name("Cert")
             .required(true)
             .multiple(true)
             .help("Public part of the secret keys managed by gpg-agent"))
        .get_matches();

    let ctx = if let Some(homedir) = matches.value_of("homedir") {
        Context::with_homedir(homedir).unwrap()
    } else {
        Context::new().unwrap()
    };

    // Read the Certs from the given files.
    let certs =
        matches.values_of("cert").expect("required").map(|f| {
            openpgp::Cert::from_file(f)
                .expect("Failed to read key")
        }).collect::<Vec<_>>();

    // Construct a KeyPair for every signing-capable (sub)key.
    let mut signers = certs.iter().flat_map(|cert| {
        cert.keys().with_policy(p, None).alive().revoked(false).for_signing()
            .filter_map(|ka| {
                KeyPair::new(&ctx, ka.key()).ok()
            })
    }).collect::<Vec<KeyPair>>();

    // Compose a writer stack corresponding to the output format and
    // packet structure we want.

    // Stream an OpenPGP message.
    let message = Message::new(io::stdout());

    // We want the output to be ASCII armored.
    let message = Armorer::new(message).build()
        .expect("Failed to create the armorer.");

    // Now, create a signer that emits the signature(s).
    let mut signer =
        Signer::new(message, signers.pop().expect("No key for signing"));
    for s in signers {
        signer = signer.add_signer(s);
    }
    let signer = signer.build().expect("Failed to create signer");

    // Then, create a literal writer to wrap the data in a literal
    // message packet.
    let mut literal = LiteralWriter::new(signer).build()
        .expect("Failed to create literal writer");

    // Copy all the data.
    io::copy(&mut io::stdin(), &mut literal)
        .expect("Failed to sign data");

    // Finally, teardown the stack to ensure all the data is written.
    literal.finalize()
        .expect("Failed to write data");
}
