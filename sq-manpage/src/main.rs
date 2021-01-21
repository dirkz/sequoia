use man::prelude::*;
use std::fs::File;
use std::io::Write;

use clap::AnyArg;

mod sq_cli;

fn main() -> std::io::Result<()> {
    let mut app = sq_cli::build();
    app = app.version("0.22.0");

    let main_manpage = create_manpage(app.clone(), None);

    let main_manpage = add_help_flag(main_manpage);
    let main_manpage = add_version_flag(main_manpage);

    let mut file = File::create(format!("{}.1", app.p.meta.name))?;
    file.write_all(main_manpage.render().as_bytes())?;

    for subcommand in app.p.subcommands {
        let sc_full_name = format!("{} {}", app.p.meta.name, subcommand.p.meta.name);
        let sc_manpage = create_manpage(subcommand.clone(), Some(&sc_full_name));
        let sc_manpage = add_help_flag(sc_manpage);

        let mut file = File::create(format!("{}-{}.1", app.p.meta.name, subcommand.p.meta.name))?;
        file.write_all(sc_manpage.render().as_bytes())?;
    }

    Ok(())
}

fn create_manpage(app: clap::App, name: Option<&str>) -> Manual {
    let name = name.unwrap_or(&app.p.meta.name);

    let mut manpage = Manual::new(&name);
    if let Some(about) = app.p.meta.about {
        manpage = manpage.about(about);
    };
    for flag in app.p.flags {
        let mut man_flag = Flag::new();
        if let Some(short) = flag.short() {
            man_flag = man_flag.short(&format!("-{}", short));
        }
        if let Some(long) = flag.long() {
            man_flag = man_flag.long(&format!("--{}", long));
        }
        if let Some(help) = flag.long_help().or(flag.help()) {
            man_flag = man_flag.help(help);
        }
        manpage = manpage.flag(man_flag);
    }
    for option in app.p.opts {
        let mut man_option = Opt::new(option.val_names().unwrap()[0]);
        if let Some(short) = option.short() {
            man_option = man_option.short(&format!("-{}", short));
        }
        if let Some(long) = option.long() {
            man_option = man_option.long(&format!("--{}", long));
        }
        if let Some(help) = option.long_help().or(option.help()) {
            man_option = man_option.help(help);
        }
        manpage = manpage.option(man_option);
    }
    for subcommand in app.p.subcommands {
        let mut  man_subcommand = Subcommand::new(&subcommand.p.meta.name);
        if let Some(about) = subcommand.p.meta.about {
            man_subcommand = man_subcommand.description(about);
        };
        manpage = manpage.subcommand(man_subcommand);
    }
    if let Some(version) = app.p.meta.version {
        manpage = manpage.version(version);
    };

    manpage
}

fn add_help_flag(manpage: Manual) -> Manual {
    let help = Flag::new()
        .short("-h")
        .long("--help")
        .help("Prints help information");
    manpage.flag(help)
}

fn add_version_flag(manpage: Manual) -> Manual {
    let version = Flag::new()
        .short("-V")
        .long("--version")
        .help("Prints version information");
    manpage.flag(version)
}