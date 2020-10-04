#![cfg_attr(feature = "unstable", allow(unstable_features))]
#![cfg_attr(feature = "unstable", feature(plugin))]
#![cfg_attr(feature = "unstable", plugin(clippy))]
//  _   _
// | |_| |__   ___  ___ __ _
// | __| '_ \ / _ \/ __/ _` |
// | |_| | | |  __/ (_| (_| |
//  \__|_| |_|\___|\___\__,_|
//
// licensed under the MIT license <http://opensource.org/licenses/MIT>
//
// lib.rs
//   main theca struct defintions and command parsing functions.

//! Definitions of Item and Profile and their implementations

extern crate core;
extern crate libc;
extern crate time;
extern crate docopt;
extern crate rustc_serialize;
extern crate regex;
extern crate crypto;
extern crate term;
extern crate rand;
extern crate tempdir;
extern crate serde;

// std lib imports
use std::env;
use std::default::Default;

// theca imports
use utils::{find_profile_folder, get_password, profiles_in_folder, extract_status};
use errors::Result;

pub use self::libc::{STDIN_FILENO, STDOUT_FILENO, STDERR_FILENO};
pub use profile::Profile;
pub use serde::Deserialize;

#[macro_use]pub mod errors;
pub mod profile;
pub mod item;
pub mod lineformat;
pub mod utils;
pub mod crypt;

/// Current version of theca
pub fn version() -> String {
    format!("theca {}", option_env!("THECA_BUILD_VER").unwrap_or(""))
}

/// theca docopt argument struct
#[derive(Debug, Deserialize, Clone)]
pub struct Args {
    pub cmd_add: bool,
    pub cmd_clear: bool,
    pub cmd_del: bool,
    pub cmd_decrypt_profile: bool,
    pub cmd_edit: bool,
    pub cmd_encrypt_profile: bool,
    pub cmd_import: bool,
    pub cmd_info: bool,
    pub cmd_list_profiles: bool,
    pub cmd_new_profile: bool,
    pub cmd_search: bool,
    pub cmd_transfer: bool,
    pub cmd__: bool,
    pub arg_id: Vec<usize>,
    pub arg_name: Vec<String>,
    pub arg_pattern: String,
    pub arg_title: String,
    pub flag_body: Vec<String>,
    pub flag_condensed: bool,
    pub flag_datesort: bool,
    pub flag_editor: bool,
    pub flag_encrypted: bool,
    pub flag_json: bool,
    pub flag_key: String,
    pub flag_limit: usize,
    pub flag_new_key: String,
    pub flag_none: bool,
    pub flag_profile: String,
    pub flag_profile_folder: String,
    pub flag_regex: bool,
    pub flag_reverse: bool,
    pub flag_search_body: bool,
    pub flag_started: bool,
    pub flag_urgent: bool,
    pub flag_version: bool,
    pub flag_yes: bool,
}

pub struct BoolFlags {
    pub condensed: bool,
    pub datesort: bool,
    pub editor: bool,
    pub encrypted: bool,
    pub json: bool,
    pub regex: bool,
    pub reverse: bool,
    pub search_body: bool,
    pub yes: bool,
}

impl BoolFlags {
    pub fn from_args(args: &Args) -> BoolFlags {
        BoolFlags {
            condensed: args.flag_condensed,
            datesort: args.flag_datesort,
            editor: args.flag_editor,
            encrypted: args.flag_encrypted,
            json: args.flag_json,
            regex: args.flag_regex,
            reverse: args.flag_reverse,
            search_body: args.flag_search_body,
            yes: args.flag_yes,
        }
    }
}

impl Default for BoolFlags {
    fn default() -> BoolFlags {
        BoolFlags {
            condensed: false,
            datesort: false,
            editor: false,
            encrypted: false,
            json: false,
            regex: false,
            reverse: false,
            search_body: false,
            yes: false,
        }
    }
}

pub fn setup_args(args: &mut Args) -> Result<()> {
    if let Ok(val) = env::var("THECA_DEFAULT_PROFILE") {
        if args.flag_profile.is_empty() && !val.is_empty() {
            args.flag_profile = val;
        }
    }

    if let Ok(val) = env::var("THECA_PROFILE_FOLDER") {
        if args.flag_profile_folder.is_empty() && !val.is_empty() {
            args.flag_profile_folder = val;
        }
    }

    // if key is provided but --encrypted not set, it prob should be
    if !args.flag_key.is_empty() && !args.flag_encrypted {
        args.flag_encrypted = true;
    }

    // if profile is encrypted try to set the key
    if args.flag_encrypted && args.flag_key.is_empty() {
        args.flag_key = get_password()?;
    }

    // if no profile is provided via cmd line or env set it to default
    if args.flag_profile.is_empty() {
        args.flag_profile = "default".to_string();
    }


    Ok(())
}

pub fn parse_cmds(profile: &mut Profile, args: &mut Args, profile_fingerprint: &u64) -> Result<()> {
    let status = extract_status(args.flag_none, args.flag_started, args.flag_urgent)?;
    let flags = BoolFlags::from_args(args);

    if [args.cmd_add,
        args.cmd_edit,
        args.cmd_encrypt_profile,
        args.cmd_del,
        args.cmd_decrypt_profile,
        args.cmd_transfer,
        args.cmd_clear,
        args.cmd_new_profile]
           .iter()
           .any(|c| c == &true) {
        // add
        if args.cmd_add {
            profile.add_note(&args.arg_title,
                                  &args.flag_body,
                                  status,
                                  args.cmd__,
                                  args.flag_editor,
                                  true)?;
        }

        // edit
        if args.cmd_edit {
            profile.edit_note(args.arg_id[0],
                                   &args.arg_title,
                                   &args.flag_body,
                                   status,
                                   args.cmd__,
                                   flags)?;
        }

        // delete
        if args.cmd_del {
            profile.delete_note(&args.arg_id);
        }

        // transfer
        if args.cmd_transfer {
            // transfer a note
            profile.transfer_note(args)?;
        }

        // clear
        if args.cmd_clear {
            profile.clear(args.flag_yes)?;
        }

        // decrypt profile
        // FIXME: should test how this interacts with save_to_file when the profile has
        //        changed during execution
        if args.cmd_decrypt_profile {
            profile.encrypted = false; // is it that easy? i think it is
            println!("decrypting '{}'", args.flag_profile);
        }

        // encrypt profile
        // FIXME: should test how this interacts with save_to_file when the profile has
        //        changed during execution
        if args.cmd_encrypt_profile {
            // get the new key
            if args.flag_new_key.is_empty() {
                args.flag_new_key = get_password()?;
            }

            // set args.key and args.encrypted
            args.flag_encrypted = true;
            args.flag_key = args.flag_new_key.clone();

            // set profile to encrypted
            profile.encrypted = true;
            println!("encrypting '{}'", args.flag_profile);
        }

        // new profile
        if args.cmd_new_profile {
            if args.cmd_new_profile && args.arg_name.is_empty() {
                args.arg_name.push("default".to_string())
            }
            println!("creating profile '{}'", args.arg_name[0]);
        }

        profile.save_to_file(args, profile_fingerprint)?;
    } else if !args.arg_id.is_empty() {
        profile.view_note(args.arg_id[0], args.flag_json, args.flag_condensed)?;
    } else if args.cmd_search {
        profile.search_notes(&args.arg_pattern, args.flag_limit, flags, status)?;
    } else if args.cmd_info {
        profile.stats(&args.flag_profile)?;
    } else if args.cmd_import {
        // reverse(?) transfer a note
        let mut from_args = args.clone();
        from_args.cmd_transfer = args.cmd_import;
        from_args.cmd_import = false;
        from_args.flag_profile = args.arg_name[0].clone();
        from_args.arg_name[0] = args.flag_profile.clone();

        let (mut from_profile, from_fingerprint) = Profile::new(
                &from_args.flag_profile,
                &from_args.flag_profile_folder,
                &from_args.flag_key,
                from_args.cmd_new_profile,
                from_args.flag_encrypted,
                from_args.flag_yes
            )?;

        parse_cmds(&mut from_profile, &mut from_args, &from_fingerprint)?;
    } else if args.cmd_list_profiles {
        let profile_path = find_profile_folder(&args.flag_profile_folder)?;
        profiles_in_folder(&profile_path)?;
    } else if args.arg_id.is_empty() {
        profile.list_notes(args.flag_limit, flags, status)?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
#![allow(non_snake_case)]
    use item::{Status, Item};
    use super::lineformat::LineFormat;

    fn write_item_test_case(item: Item, search: bool) -> String {
        let mut bytes: Vec<u8> = vec![];
        let line_format = LineFormat::new(&[item.clone()], false, false).unwrap();
        item.write(&mut bytes, &line_format, search).expect("item.write failed");
        String::from_utf8_lossy(&bytes).into_owned()
    }

    #[test]
    fn test_write_item__no_search_non_empty_body() {
        //Date without DST
        let item = Item {
            id: 0,
            title: "This is a title".into(),
            status: Status::Blank,
            body: "This is the body".into(),
            last_touched: "2016-01-08 15:31:14 -0800".into(),
        };
        assert_eq!(write_item_test_case(item, false),
                   "0   This is a title (+)  2016-01-08 18:31:14\n");
    }

    #[test]
    fn test_write_item__no_search_empty_body() {
        // no search && empty body
        //Date with DST
        let item = Item {
            id: 0,
            title: "This is a title".into(),
            status: Status::Blank,
            body: "".into(),
            last_touched: "2016-07-08 15:31:14 -0800".into(),
        };
        assert_eq!(write_item_test_case(item, false),
                   "0   This is a title  2016-07-08 19:31:14\n");
    }

    #[test]
    fn test_write_item__search_non_empty_body() {
        let item = Item {
            id: 0,
            title: "This is a title".into(),
            status: Status::Blank,
            body: "This is the body\nit has multiple lines".into(),
            last_touched: "2016-07-08 15:31:14 -0800".into(),
        };
        assert_eq!(write_item_test_case(item, true),
                   "0   This is a title      2016-07-08 19:31:14\n\tThis is the body\n\tit has \
                    multiple lines\n");
    }

    #[test]
    fn test_write_item__search_empty_body() {
        // search && empty body
        let item = Item {
            id: 0,
            title: "This is a title".into(),
            status: Status::Blank,
            body: "".into(),
            last_touched: "2016-07-08 15:31:14 -0800".into(),
        };
        assert_eq!(write_item_test_case(item, true),
                   "0   This is a title  2016-07-08 19:31:14\n");
    }

    #[test]
    fn test_write_item__non_zero_status_width() {
        let item = Item {
            id: 0,
            title: "This is a title".into(),
            status: Status::Started,
            body: "This is the body".into(),
            last_touched: "2016-07-08 15:31:14 -0800".into(),
        };
        assert_eq!(write_item_test_case(item, false),
                   "0   This is a title (+)  Started  2016-07-08 19:31:14\n");

    }
}
