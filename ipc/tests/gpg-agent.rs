//! Tests gpg-agent interaction.

use std::io::{self, Write};

extern crate futures;
use futures::future::Future;
use futures::stream::Stream;

extern crate sequoia_openpgp as openpgp;
use crate::openpgp::types::{
    HashAlgorithm,
    SymmetricAlgorithm,
};
use crate::openpgp::crypto::SessionKey;
use crate::openpgp::types::KeyFlags;
use crate::openpgp::parse::stream::*;
use crate::openpgp::serialize::{Serialize, stream::*};
use crate::openpgp::cert::{CertBuilder, CipherSuite};

extern crate sequoia_ipc as ipc;
use crate::ipc::gnupg::{Context, Agent, KeyPair};

macro_rules! make_context {
    () => {{
        let ctx = match Context::ephemeral() {
            Ok(c) => c,
            Err(e) => {
                eprintln!("SKIP: Failed to create GnuPG context: {}\n\
                           SKIP: Is GnuPG installed?", e);
                return;
            },
        };
        match ctx.start("gpg-agent") {
            Ok(_) => (),
            Err(e) => {
                eprintln!("SKIP: Failed to create GnuPG context: {}\n\
                           SKIP: Is the GnuPG agent installed?", e);
                return;
            },
        }
        ctx
    }};
}

#[test]
fn nop() {
    let ctx = make_context!();
    let mut agent = Agent::connect(&ctx).wait().unwrap();
    agent.send("NOP").unwrap();
    let response = agent.wait().collect::<Vec<_>>();
    assert_eq!(response.len(), 1);
    assert!(response[0].is_ok());
}

#[test]
fn help() {
    let ctx = make_context!();
    let mut agent = Agent::connect(&ctx).wait().unwrap();
    agent.send("HELP").unwrap();
    let response = agent.wait().collect::<Vec<_>>();
    assert!(response.len() > 3);
    assert!(response.iter().last().unwrap().is_ok());
}

const MESSAGE: &'static str = "дружба";

fn gpg_import(ctx: &Context, what: &[u8]) {
    use std::process::{Command, Stdio};

    let mut gpg = Command::new("gpg")
        .stdin(Stdio::piped())
        .arg("--homedir").arg(ctx.directory("homedir").unwrap())
        .arg("--import")
        .spawn()
        .expect("failed to start gpg");
    gpg.stdin.as_mut().unwrap().write_all(what).unwrap();
    let status = gpg.wait().unwrap();
    assert!(status.success());
}

#[test]
fn sign() {
    use self::CipherSuite::*;
    let ctx = make_context!();

    for cs in &[RSA2k, Cv25519, P521] {
        let (cert, _) = CertBuilder::new()
            .set_cipher_suite(*cs)
            .add_userid("someone@example.org")
            .add_signing_subkey()
            .generate().unwrap();

        let mut buf = Vec::new();
        cert.as_tsk().serialize(&mut buf).unwrap();
        gpg_import(&ctx, &buf);

        let keypair = KeyPair::new(
            &ctx, cert.keys_valid().for_signing().take(1).next().unwrap().2)
            .unwrap();

        let mut message = Vec::new();
        {
            // Start streaming an OpenPGP message.
            let message = Message::new(&mut message);

            // We want to sign a literal data packet.
            let signer = Signer::new(message, keypair)
                 // XXX: Is this necessary?  If so, it shouldn't.
                .hash_algo(HashAlgorithm::SHA512).unwrap()
                .build().unwrap();

            // Emit a literal data packet.
            let mut literal_writer = LiteralWriter::new(
                signer).build().unwrap();

            // Sign the data.
            literal_writer.write_all(MESSAGE.as_bytes()).unwrap();

            // Finalize the OpenPGP message to make sure that all data is
            // written.
            literal_writer.finalize().unwrap();
        }

        // Make a helper that that feeds the sender's public key to the
        // verifier.
        let helper = Helper { cert: &cert };

        // Now, create a verifier with a helper using the given Certs.
        let mut verifier =
            Verifier::from_bytes(&message, helper, None).unwrap();

        // Verify the data.
        let mut sink = Vec::new();
        io::copy(&mut verifier, &mut sink).unwrap();
        assert_eq!(MESSAGE.as_bytes(), &sink[..]);
    }

    struct Helper<'a> {
        cert: &'a openpgp::Cert,
    }

    impl<'a> VerificationHelper for Helper<'a> {
        fn get_public_keys(&mut self, _ids: &[openpgp::KeyHandle])
                           -> openpgp::Result<Vec<openpgp::Cert>> {
            // Return public keys for signature verification here.
            Ok(vec![self.cert.clone()])
        }

        fn check(&mut self, structure: &MessageStructure)
                 -> openpgp::Result<()> {
            // In this function, we implement our signature verification
            // policy.

            let mut good = false;
            for (i, layer) in structure.iter().enumerate() {
                match (i, layer) {
                    // First, we are interested in signatures over the
                    // data, i.e. level 0 signatures.
                    (0, MessageLayer::SignatureGroup { ref results }) => {
                        // Finally, given a VerificationResult, which only says
                        // whether the signature checks out mathematically, we apply
                        // our policy.
                        match results.get(0) {
                            Some(VerificationResult::GoodChecksum { .. }) =>
                                good = true,
                            Some(VerificationResult::NotAlive { .. }) =>
                                return Err(failure::err_msg(
                                    "Good, but not live signature")),
                            Some(VerificationResult::MissingKey { .. }) =>
                                return Err(failure::err_msg(
                                    "Missing key to verify signature")),
                            Some(VerificationResult::BadChecksum { .. }) =>
                                return Err(failure::err_msg("Bad signature")),
                            None =>
                                return Err(failure::err_msg("No signature")),
                        }
                    },
                    _ => return Err(failure::err_msg(
                        "Unexpected message structure")),
                }
            }

            if good {
                Ok(()) // Good signature.
            } else {
                Err(failure::err_msg("Signature verification failed"))
            }
        }
    }
}

#[test]
fn decrypt() {
    use self::CipherSuite::*;
    let ctx = make_context!();

    for cs in &[RSA2k, Cv25519, P521] {
        let (cert, _) = CertBuilder::new()
            .set_cipher_suite(*cs)
            .add_userid("someone@example.org")
            .add_transport_encryption_subkey()
            .generate().unwrap();

        let mut buf = Vec::new();
        cert.as_tsk().serialize(&mut buf).unwrap();
        gpg_import(&ctx, &buf);

        let mut message = Vec::new();
        {
            let recipient =
                cert.keys_valid().key_flags(
                    KeyFlags::default().set_transport_encryption(true))
                .map(|(_, _, key)| key.into())
                .nth(0).unwrap();

            // Start streaming an OpenPGP message.
            let message = Message::new(&mut message);

            // We want to encrypt a literal data packet.
            let encryptor =
                Encryptor::for_recipient(message, recipient).build().unwrap();

            // Emit a literal data packet.
            let mut literal_writer = LiteralWriter::new(
                encryptor).build().unwrap();

            // Encrypt the data.
            literal_writer.write_all(MESSAGE.as_bytes()).unwrap();

            // Finalize the OpenPGP message to make sure that all data is
            // written.
            literal_writer.finalize().unwrap();
        }

        // Make a helper that that feeds the recipient's secret key to the
        // decryptor.
        let helper = Helper { ctx: &ctx, cert: &cert, };

        // Now, create a decryptor with a helper using the given Certs.
        let mut decryptor = Decryptor::from_bytes(&message, helper, None)
            .unwrap();

        // Decrypt the data.
        let mut sink = Vec::new();
        io::copy(&mut decryptor, &mut sink).unwrap();
        assert_eq!(MESSAGE.as_bytes(), &sink[..]);

        struct Helper<'a> {
            ctx: &'a Context,
            cert: &'a openpgp::Cert,
        }

        impl<'a> VerificationHelper for Helper<'a> {
            fn get_public_keys(&mut self, _ids: &[openpgp::KeyHandle])
                               -> openpgp::Result<Vec<openpgp::Cert>> {
                // Return public keys for signature verification here.
                Ok(Vec::new())
            }

            fn check(&mut self, _structure: &MessageStructure)
                     -> openpgp::Result<()> {
                // Implement your signature verification policy here.
                Ok(())
            }
        }

        impl<'a> DecryptionHelper for Helper<'a> {
            fn decrypt<D>(&mut self,
                          pkesks: &[openpgp::packet::PKESK],
                          _skesks: &[openpgp::packet::SKESK],
                          mut decrypt: D)
                          -> openpgp::Result<Option<openpgp::Fingerprint>>
                where D: FnMut(SymmetricAlgorithm, &SessionKey) ->
                      openpgp::Result<()>
            {
                let mut keypair = KeyPair::new(
                    self.ctx,
                    self.cert.keys_valid().key_flags(
                        KeyFlags::default().set_transport_encryption(true))
                        .take(1).next().unwrap().2)
                    .unwrap();

                pkesks[0].decrypt(&mut keypair)
                    .and_then(|(algo, session_key)| decrypt(algo, &session_key))
                    .map(|_| None)
                // XXX: In production code, return the Fingerprint of the
                // recipient's Cert here
            }
        }
    }
}
