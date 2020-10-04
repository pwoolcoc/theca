// std lib imports
use std::io::{stdin, Read, Write};
use std::fs::{File, create_dir};

// random things
use regex::Regex;
use rustc_serialize::Encodable;
use rustc_serialize::json::{decode, as_pretty_json, Encoder};
use time::OffsetDateTime;

// theca imports
use utils::c::istty;
use utils::{drop_to_editor, pretty_line, get_yn_input, sorted_print, localize_last_touched_string,
            parse_last_touched, find_profile_folder, profile_fingerprint};
use errors::{Result, Error};
use crypt::{encrypt, decrypt, password_to_key};
use item::{Status, Item};

pub use libc::{STDIN_FILENO, STDOUT_FILENO, STDERR_FILENO};

use {parse_cmds, Args, BoolFlags};

/// datetime formating string
pub static DATEFMT: &'static str = "%F %T %z";
/// short datetime formating string for printing
pub static DATEFMT_SHORT: &'static str = "%F %T";

/// Main container of a theca profile file
#[derive(RustcDecodable, RustcEncodable, Clone)]
pub struct Profile {
    pub encrypted: bool,
    pub notes: Vec<Item>,
}

impl Profile {
    fn from_scratch(profile_folder: &str, encrypted: bool, yes: bool) -> Result<(Profile, u64)> {
        let profile_path = find_profile_folder(profile_folder)?;
        // if the folder doesn't exist, make it yo!
        if !profile_path.exists() {
            if !yes {
                let message = format!("{} doesn't exist, would you like to create it?\n",
                                      profile_path.display());
                if !get_yn_input(&message)? {
                    return specific_fail_str!("ok bye ♥");
                }
            }
            create_dir(&profile_path)?;
        }
        Ok((Profile {
            encrypted: encrypted,
            notes: vec![],
        },
            0u64))
    }

    fn from_existing_profile(profile_name: &str,
                             profile_folder: &str,
                             key: &str,
                             encrypted: bool)
                             -> Result<(Profile, u64)> {
        // set profile folder
        let mut profile_path = find_profile_folder(profile_folder)?;

        // set profile name
        profile_path.push(&(profile_name.to_string() + ".json"));

        // attempt to read profile
        if profile_path.is_file() {
            let mut file = File::open(&profile_path)?;
            let mut contents_buf = vec![];
            file.read_to_end(&mut contents_buf)?;
            let contents = if encrypted {
                let key = password_to_key(&key[..]);
                String::from_utf8(decrypt(&*contents_buf, &*key)?)?
            } else {
                String::from_utf8(contents_buf)?
            };
            let decoded: Profile = match decode(&*contents) {
                Ok(s) => s,
                Err(_) => {
                    return specific_fail!(format!("invalid JSON in {}", profile_path.display()))
                }
            };
            let fingerprint = profile_fingerprint(profile_path)?;
            Ok((decoded, fingerprint))
        } else if profile_path.exists() {
            specific_fail!(format!("{} is not a file.", profile_path.display()))
        } else {
            specific_fail!(format!("{} does not exist.", profile_path.display()))
        }
    }

    /// setup a Profile struct based on the command line arguments
    pub fn new(profile_name: &str,
               profile_folder: &str,
               key: &str,
               new_profile: bool,
               encrypted: bool,
               yes: bool)
               -> Result<(Profile, u64)> {
        if new_profile {
            Profile::from_scratch(profile_folder, encrypted, yes)
        } else {
            Profile::from_existing_profile(profile_name, profile_folder, key, encrypted)
        }
    }

    /// remove all notes from the profile
    pub fn clear(&mut self, yes: bool) -> Result<()> {
        if !yes {
            let message = "are you sure you want to delete all the notes in this profile?\n";
            if !get_yn_input(&message)? {
                return specific_fail_str!("ok bye ♥");
            }
        }
        self.notes.truncate(0);
        Ok(())
    }

    // FIXME (this as well as transfer_note, shouldn't *need* to take all of `args`)
    /// save the profile back to file (either plaintext or encrypted)
    pub fn save_to_file(&mut self, args: &Args, fingerprint: &u64) -> Result<()> {
        // set profile folder
        let mut profile_path = find_profile_folder(&args.flag_profile_folder)?;

        // set file name
        if args.cmd_new_profile {
            profile_path.push(&(args.arg_name[0].to_string() + ".json"));
        } else {
            profile_path.push(&(args.flag_profile.to_string() + ".json"));
        }

        if args.cmd_new_profile && profile_path.exists() && !args.flag_yes {
            let message = format!("profile {} already exists would you like to overwrite it?\n",
                                  profile_path.display());
            if !get_yn_input(&message)? {
                return specific_fail_str!("ok bye ♥");
            }
        }

        if fingerprint > &0u64 {
            let new_fingerprint = profile_fingerprint(&profile_path)?;
            if &new_fingerprint != fingerprint && !args.flag_yes {
                let message = format!("changes have been made to the profile '{}' on disk since \
                                       it was loaded, would you like to attempt to merge them?\n",
                                      args.flag_profile);
                if !get_yn_input(&message)? {
                    return specific_fail_str!("ok bye ♥");
                }
                let mut new_args = args.clone();
                if args.flag_editor {
                    new_args.flag_editor = false;
                    new_args.flag_body[0] = match self.notes.last() {
                        Some(n) => n.body.clone(),
                        None => "".to_string(),
                    };
                }
                let (mut changed_profile, changed_fingerprint) = Profile::new(
                    &new_args.flag_profile,
                    &new_args.flag_profile_folder,
                    &new_args.flag_key,
                    new_args.cmd_new_profile,
                    new_args.flag_encrypted,
                    new_args.flag_yes
                    )?;
                parse_cmds(&mut changed_profile, &mut new_args, &changed_fingerprint)?;
                changed_profile.save_to_file(&new_args, &0u64)?;
                return Ok(());
            }
        }

        // open file
        let mut file = File::create(profile_path)?;

        // encode to buffer
        let mut json_prof = String::new();
        {
            let mut encoder = Encoder::new_pretty(&mut json_prof);
            self.encode(&mut encoder)?;
        }

        // encrypt json if its an encrypted profile
        let buffer = if self.encrypted {
            let key = password_to_key(&*args.flag_key);
            encrypt(&json_prof.into_bytes(), &*key)?
        } else {
            json_prof.into_bytes()
        };

        // write buffer to file
        file.write_all(&buffer)?;

        Ok(())
    }

    // FIXME (this as well as save_to_file, shouldn't *need* to take all of `args`)
    /// transfer a note from the profile to another profile
    pub fn transfer_note(&mut self, args: &Args) -> Result<()> {
        if args.flag_profile == args.arg_name[0] {
            return specific_fail!(format!("cannot transfer a note from a profile to itself ({} \
                                           -> {})",
                                          args.flag_profile,
                                          args.arg_name[0]));
        }

        let mut trans_args = args.clone();
        trans_args.flag_profile = args.arg_name[0].clone();
        let (mut trans_profile, trans_fingerprint) = Profile::new(&args.arg_name[0],
                                                                       &args.flag_profile_folder,
                                                                       &args.flag_key,
                                                                       args.cmd_new_profile,
                                                                       args.flag_encrypted,
                                                                       args.flag_yes)?;

        if self.notes
               .iter()
               .find(|n| n.id == args.arg_id[0])
               .map(|n| {
                   trans_profile.add_note(&n.title,
                                          &[n.body.clone()],
                                          Some(n.status),
                                          false,
                                          false,
                                          false)
               })
               .is_some() {
            if self.notes
                   .iter()
                   .position(|n| n.id == args.arg_id[0])
                   .map(|e| self.notes.remove(e))
                   .is_some() {
                trans_profile.save_to_file(&trans_args, &trans_fingerprint)?
            } else {
                return specific_fail!(format!("couldn't remove note {} in {}, aborting nothing \
                                               will be saved",
                                              args.arg_id[0],
                                              args.flag_profile));
            }
        } else {
            return specific_fail!(format!("could not transfer note {} from {} -> {}",
                                          args.arg_id[0],
                                          args.flag_profile,
                                          args.arg_name[0]));
        }
        println!("transfered [{}: note {} -> {}: note {}]",
                 args.flag_profile,
                 args.arg_id[0],
                 args.arg_name[0],
                 trans_profile.notes.last().map_or(0, |n| n.id));
        Ok(())
    }

    /// add a item to the profile
    pub fn add_note(&mut self,
                    title: &str,
                    body: &[String],
                    status: Option<Status>,
                    use_stdin: bool,
                    use_editor: bool,
                    print_msg: bool)
                    -> Result<()> {
        let title = title.replace("\n", "").to_string();

        let body = if use_stdin {
            let mut buf = String::new();
            stdin().read_to_string(&mut buf)?;
            buf.to_owned()
        } else if !use_editor {
            if body.is_empty() {
                "".to_string()
            } else {
                body[0].clone()
            }
        } else if istty(STDOUT_FILENO) && istty(STDIN_FILENO) {
            drop_to_editor(&"".to_string())?
        } else {
            "".to_string()
        };

        let new_id = match self.notes.last() {
            Some(n) => n.id,
            None => 0,
        };
        self.notes.push(Item {
            id: new_id + 1,
            title: title,
            status: status.unwrap_or(Status::Blank),
            body: body,
            //last_touched: strftime(DATEFMT, &now())?,
            last_touched: OffsetDateTime::now_local().format(DATEFMT),
        });
        if print_msg {
            println!("note {} added", new_id + 1);
        }
        Ok(())
    }

    /// delete an item from the profile
    pub fn delete_note(&mut self, id: &[usize]) {
        for nid in id.iter() {
            let remove = self.notes
                             .iter()
                             .position(|n| &n.id == nid)
                             .map(|e| self.notes.remove(e))
                             .is_some();
            if remove {
                println!("deleted note {}", nid);
            } else {
                println!("note {} doesn't exist", nid);
            }
        }
    }

    /// edit an item in the profile
    pub fn edit_note(&mut self,
                     id: usize,
                     title: &str,
                     body: &[String],
                     status: Option<Status>,
                     use_stdin: bool,
                     flags: BoolFlags)
                     -> Result<()> {
        // let id = args.arg_id[0];
        let item_pos: usize = match self.notes.iter().position(|n| n.id == id) {
            Some(i) => i,
            None => return specific_fail!(format!("note {} doesn't exist", id)),
        };
        let use_editor = flags.editor;
        let encrypted = flags.encrypted;
        let yes = flags.yes;
        if !title.is_empty() {
            if title.replace("\n", "") == "-" {
                if !use_stdin {
                    let mut buf = String::new();
                    stdin().read_to_string(&mut buf)?;
                    self.notes[item_pos].body = buf.to_owned();
                } else {
                    self.notes[item_pos].title = title.replace("\n", "")
                                                      .to_string()
                }
            } else {
                self.notes[item_pos].title = title.replace("\n", "")
                                                  .to_string()
            }
            // change title
        }
        self.notes[item_pos].status = status.unwrap_or(Status::Blank);

        if !body.is_empty() || use_editor || use_stdin {
            // change body
            self.notes[item_pos].body = if use_stdin {
                let mut buf = String::new();
                stdin().read_to_string(&mut buf)?;
                buf.to_owned()
            } else if use_editor {
                if istty(STDOUT_FILENO) && istty(STDIN_FILENO) {
                    if encrypted && !yes {
                        let message = format!("{0}\n\n{1}\n{2}\n\n{0}\n{3}\n",
                                              "## [WARNING] ##",
                                              "continuing will write the body of the decrypted \
                                               note to a temporary",
                                              "file, increasing the possibilty it could be \
                                               recovered later.",
                                              "Are you sure you want to continue?\n");
                        if !get_yn_input(&message)? {
                            return specific_fail_str!("ok bye ♥");
                        }
                    }
                    let new_body = drop_to_editor(&self.notes[item_pos].body)?;
                    if self.notes[item_pos].body != new_body {
                        new_body
                    } else {
                        self.notes[item_pos].body.clone()
                    }
                } else {
                    self.notes[item_pos].body.clone()
                }
            } else {
                body[0].clone()
            }
        };

        // update last_touched
        self.notes[item_pos].last_touched = OffsetDateTime::now_local().format(DATEFMT);
        println!("edited note {}", self.notes[item_pos].id);
        Ok(())
    }

    /// print information about the profile
    pub fn stats(&mut self, name: &str) -> Result<()> {
        let no_s = self.notes.iter().filter(|n| n.status == Status::Blank).count();
        let started_s = self.notes
                            .iter()
                            .filter(|n| n.status == Status::Started)
                            .count();
        let urgent_s = self.notes
                           .iter()
                           .filter(|n| n.status == Status::Urgent)
                           .count();
        let tty = istty(STDOUT_FILENO);
        let min = match self.notes
                            .iter()
                            .min_by_key(|n| match parse_last_touched(&*n.last_touched) {
                                Ok(o) => o,
                                Err(_) => OffsetDateTime::now_local(),
                            }) {
            Some(n) => localize_last_touched_string(&*n.last_touched)?,
            None => return specific_fail_str!("last_touched is not properly formated"),
        };
        let max = match self.notes
                            .iter()
                            .max_by_key(|n| match parse_last_touched(&*n.last_touched) {
                                Ok(o) => o,
                                Err(_) => OffsetDateTime::now_local(),
                            }) {
            Some(n) => localize_last_touched_string(&*n.last_touched)?,
            None => return specific_fail_str!("last_touched is not properly formated"),
        };
        pretty_line("name: ", &format!("{}\n", name), tty)?;
        pretty_line("encrypted: ", &format!("{}\n", self.encrypted), tty)?;
        pretty_line("notes: ", &format!("{}\n", self.notes.len()), tty)?;
        pretty_line("statuses: ",
                         &format!("none: {}, started: {}, urgent: {}\n",
                                  no_s,
                                  started_s,
                                  urgent_s),
                         tty)?;
        pretty_line("note ages: ",
                         &format!("oldest: {}, newest: {}\n", min, max),
                         tty)?;
        Ok(())
    }

    /// print a full item
    pub fn view_note(&mut self, id: usize, json: bool, condensed: bool) -> Result<()> {
        let id = id;
        let note_pos = match self.notes.iter().position(|n| n.id == id) {
            Some(i) => i,
            None => return specific_fail!(format!("note {} doesn't exist", id)),
        };
        if json {
            println!("{}", as_pretty_json(&self.notes[note_pos].clone()));
        } else {
            let tty = istty(STDOUT_FILENO);

            if condensed {
                pretty_line("id: ", &format!("{}\n", self.notes[note_pos].id), tty)?;
                pretty_line("title: ", &format!("{}\n", self.notes[note_pos].title), tty)?;
                if self.notes[note_pos].status != Status::Blank {
                pretty_line("status: ",
                                 &format!("{}\n", self.notes[note_pos].status),
                                 tty)?;
                }
                pretty_line("last touched: ",
                             &format!("{}\n",
                            localize_last_touched_string(
                                &*self.notes[note_pos].last_touched
                            )
                        ?),
                             tty)?;
            } else {
                pretty_line("id\n--\n", &format!("{}\n\n", self.notes[note_pos].id), tty)?;
                pretty_line("title\n-----\n",
                                 &format!("{}\n\n", self.notes[note_pos].title),
                                 tty)?;
                if self.notes[note_pos].status != Status::Blank {
                    pretty_line("status\n------\n",
                                     &format!("{:?}\n\n", self.notes[note_pos].status),
                                     tty)?;
                }
                pretty_line("last touched\n------------\n",
                                 &format!("{}\n\n",
                                localize_last_touched_string(
                                    &*self.notes[note_pos].last_touched
                                )
                            ?),
                                 tty)?;
            };

            // body
            if !self.notes[note_pos].body.is_empty() {
                if condensed {
                    pretty_line("body: ", &format!("{}\n", self.notes[note_pos].body), tty)?;
                } else {
                    pretty_line("body\n----\n",
                                     &format!("{}\n\n", self.notes[note_pos].body),
                                     tty)?;
                };
            }
        }
        Ok(())
    }

    /// print all notes in the profile
    pub fn list_notes(&mut self,
                      limit: usize,
                      flags: BoolFlags,
                      status: Option<Status>)
                      -> Result<()> {
        if !self.notes.is_empty() {
            sorted_print(&mut self.notes.clone(), limit, flags, status)?;
        } else if flags.json {
            println!("[]");
        } else {
            println!("this profile is empty");
        }
        Ok(())
    }

    /// print notes search for in the profile
    pub fn search_notes(&mut self,
                        pattern: &str,
                        limit: usize,
                        flags: BoolFlags,
                        status: Option<Status>)
                        -> Result<()> {
        let notes: Vec<Item> = if flags.regex {
            let re = match Regex::new(&pattern[..]) {
                Ok(r) => r,
                Err(e) => return specific_fail!(format!("regex error: {}.", e)),
            };
            self.notes
                .iter()
                .filter(|n| if flags.search_body {
                    re.is_match(&*n.body)
                } else {
                    re.is_match(&*n.title)
                })
                .cloned()
                .collect()
        } else {
            self.notes
                .iter()
                .filter(|n| if flags.search_body {
                    n.body.contains(&pattern[..])
                } else {
                    n.title.contains(&pattern[..])
                })
                .cloned()
                .collect()
        };
        if !notes.is_empty() {
            sorted_print(&mut notes.clone(), limit, flags, status)?;
        } else if flags.json {
            println!("[]");
        } else {
            println!("nothing found");
        }
        Ok(())
    }
}
