use clap::{App, Arg, SubCommand, AppSettings};

pub fn build() -> App<'static, 'static> {
    App::new("sq")
        .version("0.1.0")
        .about("Sequoia is an implementation of OpenPGP.  This is a command-line frontend.")
        .setting(AppSettings::ArgRequiredElseHelp)
        .arg(Arg::with_name("domain").value_name("DOMAIN")
             .long("domain")
             .short("d")
             .help("Sets the domain to use"))
        .arg(Arg::with_name("policy").value_name("NETWORK-POLICY")
             .long("policy")
             .short("p")
             .help("Sets the network policy to use"))
        .subcommand(SubCommand::with_name("decrypt")
                    .about("Decrypts an OpenPGP message")
                    .arg(Arg::with_name("input").value_name("FILE")
                         .long("input")
                         .short("i")
                         .help("Sets the input file to use"))
                    .arg(Arg::with_name("output").value_name("FILE")
                         .long("output")
                         .short("o")
                         .help("Sets the output file to use"))
                    .arg(Arg::with_name("dearmor")
                         .long("dearmor")
                         .short("A")
                         .help("Remove ASCII Armor from input"))
                    .arg(Arg::with_name("dump")
                         .long("dump")
                         .help("Print a packet dump to stderr"))
                    .arg(Arg::with_name("hex")
                         .long("hex")
                         .short("x")
                         .help("Print a hexdump (implies --dump)")))
        .subcommand(SubCommand::with_name("enarmor")
                    .about("Applies ASCII Armor to a file")
                    .arg(Arg::with_name("input").value_name("FILE")
                         .long("input")
                         .short("i")
                         .help("Sets the input file to use"))
                    .arg(Arg::with_name("output").value_name("FILE")
                         .long("output")
                         .short("o")
                         .help("Sets the output file to use")))
        .subcommand(SubCommand::with_name("dearmor")
                    .about("Removes ASCII Armor from a file")
                    .arg(Arg::with_name("input").value_name("FILE")
                         .long("input")
                         .short("i")
                         .help("Sets the input file to use"))
                    .arg(Arg::with_name("output").value_name("FILE")
                         .long("output")
                         .short("o")
                         .help("Sets the output file to use")))
        .subcommand(SubCommand::with_name("dump")
                    .about("Lists OpenPGP packets")
                    .arg(Arg::with_name("input").value_name("FILE")
                         .long("input")
                         .short("i")
                         .help("Sets the input file to use"))
                    .arg(Arg::with_name("output").value_name("FILE")
                         .long("output")
                         .short("o")
                         .help("Sets the output file to use"))
                    .arg(Arg::with_name("dearmor")
                         .long("dearmor")
                         .short("A")
                         .help("Remove ASCII Armor from input"))
                    .arg(Arg::with_name("hex")
                         .long("hex")
                         .short("x")
                         .help("Print a hexdump")))
        .subcommand(SubCommand::with_name("keyserver")
                    .about("Interacts with keyservers")
                    .arg(Arg::with_name("server").value_name("URI")
                         .long("server")
                         .short("s")
                         .help("Sets the keyserver to use"))
                    .subcommand(SubCommand::with_name("get")
                                .about("Retrieves a key")
                                .arg(Arg::with_name("output").value_name("FILE")
                                     .long("output")
                                     .short("o")
                                     .help("Sets the output file to use"))
                                .arg(Arg::with_name("armor")
                                     .long("armor")
                                     .short("A")
                                     .help("Write armored data to file"))
                                .arg(Arg::with_name("keyid").value_name("KEYID")
                                     .required(true)
                                     .help("ID of the key to retrieve")))
                    .subcommand(SubCommand::with_name("send")
                                .about("Sends a key")
                                .arg(Arg::with_name("input").value_name("FILE")
                                     .long("input")
                                     .short("i")
                                     .help("Sets the input file to use"))
                                .arg(Arg::with_name("dearmor")
                                     .long("dearmor")
                                     .short("A")
                                     .help("Remove ASCII Armor from input"))))
        .subcommand(SubCommand::with_name("store")
                    .about("Interacts with key stores")
                    .arg(Arg::with_name("name").value_name("NAME")
                         .required(true)
                         .help("Name of the store"))
                    .subcommand(SubCommand::with_name("list")
                                .about("Lists keys in the store"))
                    .subcommand(SubCommand::with_name("add")
                                .about("Add a key identified by fingerprint")
                                .arg(Arg::with_name("label").value_name("LABEL")
                                     .required(true)
                                     .help("Label to use"))
                                .arg(Arg::with_name("fingerprint").value_name("FINGERPRINT")
                                     .required(true)
                                     .help("Key to add")))
                    .subcommand(SubCommand::with_name("import")
                                .about("Imports a key")
                                .arg(Arg::with_name("label").value_name("LABEL")
                                     .required(true)
                                     .help("Label to use"))
                                .arg(Arg::with_name("input").value_name("FILE")
                                     .long("input")
                                     .short("i")
                                     .help("Sets the input file to use"))
                                .arg(Arg::with_name("dearmor")
                                     .long("dearmor")
                                     .short("A")
                                     .help("Remove ASCII Armor from input")))
                    .subcommand(SubCommand::with_name("export")
                                .about("Exports a key")
                                .arg(Arg::with_name("label").value_name("LABEL")
                                     .required(true)
                                     .help("Label to use"))
                                .arg(Arg::with_name("output").value_name("FILE")
                                     .long("output")
                                     .short("o")
                                     .help("Sets the output file to use"))
                                .arg(Arg::with_name("armor")
                                     .long("armor")
                                     .short("A")
                                     .help("Write armored data to file")))
                    .subcommand(SubCommand::with_name("delete")
                                .about("Deletes bindings or stores")
                                .arg(Arg::with_name("the-store")
                                     .long("the-store")
                                     .help("Delete the whole store"))
                                .arg(Arg::with_name("label")
                                     .value_name("LABEL")
                                     .help("Delete binding with this label")))
                    .subcommand(SubCommand::with_name("stats")
                                .about("Get stats for the given label")
                                .arg(Arg::with_name("label").value_name("LABEL")
                                     .required(true)
                                     .help("Label to use")))
                    .subcommand(SubCommand::with_name("log")
                                .about("Lists the keystore log")
                                .arg(Arg::with_name("label")
                                     .value_name("LABEL")
                                     .help("List messages related to this label"))))
        .subcommand(SubCommand::with_name("list")
                    .about("Lists key stores and known keys")
                    .subcommand(SubCommand::with_name("stores")
                                .about("Lists key stores")
                                .arg(Arg::with_name("prefix").value_name("PREFIX")
                                     .help("List only stores with the given domain prefix")))
                    .subcommand(SubCommand::with_name("bindings")
                                .about("Lists all bindings in all key stores")
                                .arg(Arg::with_name("prefix").value_name("PREFIX")
                                     .help("List only bindings from stores with the given domain prefix")))
                    .subcommand(SubCommand::with_name("keys")
                                .about("Lists all keys in the common key pool"))
                    .subcommand(SubCommand::with_name("log")
                                .about("Lists the server log")))
}
