use man::prelude::*;
use std::fs::File;
use std::io::Write;

use clap::{AnyArg, ArgSettings};

mod sq_cli;

fn main() -> std::io::Result<()> {
    let app = sq_cli::build();

    let mut manpages = Vec::new();
    create_manpage(app.clone(), None, &mut manpages);

    let manpage_names = manpages
        .iter()
        .map(|man| man.name.clone())
        .collect::<Vec<String>>();
    let related = manpage_names
        .clone()
        .iter()
        .cloned()
        .map(|man| find_related(&man, manpage_names.clone()))
        .collect::<Vec<Vec<String>>>();
    let man_plus_related = manpages.into_iter().zip(related);

    fn find_related(name: &str, mut candidates: Vec<String>) -> Vec<String> {
        //reconstruct structure
        let top_level =
            candidates.iter().position(|name| name == "sq").unwrap();
        let top_level = candidates.remove(top_level);
        let (second_level, third_level): (Vec<String>, Vec<String>) =
            candidates.iter().cloned().partition(|name| {
                name.split(' ').collect::<Vec<&str>>().len() == 2
            });

        //Always include first and second level commands
        let mut output = second_level.clone();
        output.push(top_level);

        let subcommand: Option<String> =
            second_level.iter().cloned().find(|sl| name.contains(sl));
        if let Some(sc) = subcommand {
            let mut tl = third_level
                .into_iter()
                .filter(|tl| tl.contains(&sc))
                .collect::<Vec<String>>();
            output.append(&mut tl);
        }
        output.sort_unstable();
        output.dedup();
        output
    }

    for (mut manpage, related) in man_plus_related {
        let related = related
            .iter()
            .map(|related| [&related.replace(" ", "-"), "(1)"].join(""))
            .collect::<Vec<String>>()
            .join(", ");
        let see_also = Section::new("See also")
            .paragraph("For the full documentation see <https://docs.sequoia-pgp.org/sq/>.")
            // don't justify and don't hyphenate
            .paragraph(&[".ad l\n.nh\n", &related].join(""));

        manpage = manpage.custom(see_also.clone());
        write_manpage(manpage)?;
    }

    Ok(())
}

fn create_manpage(
    app: clap::App,
    outer_name: Option<&str>,
    manpages: &mut Vec<Manual>,
) {
    let name = match outer_name {
        Some(outer_name) => [outer_name, &app.p.meta.name].join(" "),
        None => app.p.meta.name,
    };
    let mut manpage = Manual::new(&name);
    manpage = add_authors(manpage);
    manpage = manpage.date("January 2021");
    manpage = add_help_flag(manpage);
    if outer_name.is_none() {
        manpage = add_version_flag(manpage);
    }

    if let Some(about) = app
        .p
        .meta
        .long_about
        .filter(|la| !la.is_empty())
        .or(app.p.meta.about)
    {
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
        // prefer val_name over name. why though?
        let name = option.val_names().map_or(option.name(), |vn| vn[0]);
        let mut man_option = Opt::new(name);
        if let Some(short) = option.short() {
            man_option = man_option.short(&format!("-{}", short));
        }
        if let Some(long) = option.long() {
            man_option = man_option.long(&format!("--{}", long));
        }
        if let Some(help) = option.long_help().or(option.help()) {
            let possible_values =
                option.possible_vals().map_or("".into(), |pvs| {
                    ["  [possible values: ", &pvs.join(", "), "]"].join("")
                });
            let default_value = option.default_val().map_or("".into(), |dv| {
                ["  [default: ", &dv.to_string_lossy(), "]"].join("")
            });
            let help = [help, &default_value, &possible_values].join("");
            man_option = man_option.help(&help);
        }
        manpage = manpage.option(man_option);
    }
    for arg in app.p.positionals {
        //arg is a pair of (count, Arg)
        let arg = arg.1;
        let val_name = arg.val_names().unwrap()[0];
        let required = arg.is_set(ArgSettings::Required);
        let mut man_arg = man::Arg::new(val_name, required);
        if let Some(help) = arg.long_help().or(arg.help()) {
            man_arg = man_arg.description(help);
        }
        manpage = manpage.arg(man_arg);
    }
    if !app.p.subcommands.is_empty() {
        manpage = add_help_subcommand(manpage);
    };
    for subcommand in app.p.subcommands.clone() {
        let sc_meta = subcommand.p.meta;
        let mut man_subcommand = Subcommand::new(&sc_meta.name);
        if let Some(about) = sc_meta
            .long_about
            .filter(|la| !la.is_empty())
            .or(sc_meta.about)
        {
            man_subcommand = man_subcommand.description(about);
        };
        manpage = manpage.subcommand(man_subcommand);
    }
    if let Some(more_help) = app.p.meta.more_help {
        // this is specific to sequoia
        if more_help.starts_with("EXAMPLE") {
            manpage = add_examples(manpage, more_help);
        } else {
            let example = Example::new().text(&more_help).prompt("");
            manpage = manpage.example(example);
        }
    }
    if let Some(version) = app.p.meta.version {
        manpage = manpage.version(version);
    };

    for subcommand in app.p.subcommands {
        create_manpage(subcommand.clone(), Some(&name), manpages);
    }

    manpages.push(manpage);
}

fn add_authors(mut manpage: Manual) -> Manual {
    let authors = [
        "Justus Winter <justus@sequoia-pgp.org>",
        "Kai Michaelis <kai@sequoia-pgp.org>",
        "Neal H. Walfield <neal@sequoia-pgp.org>",
    ];
    for author in authors.iter() {
        let mut split = author.split(" <");
        let name = split.next().unwrap();
        let email = split.next().unwrap().replace(">", "");
        let author = Author::new(name).email(&email);
        manpage = manpage.author(author);
    }
    manpage
}

/// Parse examples from clap's after_help (called more_help internally)
fn add_examples(mut manpage: Manual, more_help: &str) -> Manual {
    let mut lines_iter = more_help.lines();
    while let Some(line) = lines_iter.next() {
        if line.is_empty() || line.contains("EXAMPLE") {
            continue;
        } else {
            let text = line.replace("# ", "");
            let command = lines_iter.next().expect("command example expected");
            let command = command.replace("$ ", "");
            let example = Example::new().text(&text).command(&command);
            manpage = manpage.example(example);
        }
    }
    manpage
}

fn add_help_subcommand(manpage: Manual) -> Manual {
    let help = Subcommand::new("help").description(
        "Prints this message or the help of the given subcommand(s)",
    );
    manpage.subcommand(help)
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

fn write_manpage(manpage: Manual) -> std::io::Result<()> {
    let mut file =
        File::create(format!("{}.1", manpage.name.replace(" ", "-")))?;
    file.write_all(manpage.render().as_bytes())
}
