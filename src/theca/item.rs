use std::fmt;
use std::iter::repeat;
use std::io::{self, Write};

use rustc_serialize::{self, Decodable, Encodable};

use lineformat::LineFormat;
use utils::{format_field, localize_last_touched_string};
use errors::Result;

/// Represents a note within a profile
#[derive(RustcDecodable, RustcEncodable, Clone, Debug)]
pub struct Item {
    pub id: usize,
    pub title: String,
    pub status: Status,
    pub body: String,
    pub last_touched: String,
}

impl Item {
    /// print a note as a line
    pub fn print(&self, line_format: &LineFormat, search_body: bool) -> Result<()> {
        self.write(&mut io::stdout(), line_format, search_body)
    }

    pub fn write<T: Write>(&self,
                           output: &mut T,
                           line_format: &LineFormat,
                           search_body: bool)
                           -> Result<()> {
        let column_seperator: String = repeat(' ')
                                           .take(line_format.colsep)
                                           .collect();
        write!(output,
                    "{}",
                    format_field(&self.id.to_string(), line_format.id_width, false))?;
        write!(output, "{}", column_seperator)?;
        if !self.body.is_empty() && !search_body {
            write!(output,
                        "{}",
                        format_field(&self.title, line_format.title_width - 4, true))?;
            write!(output, "{}", format_field(&" (+)".to_string(), 4, false))?;
        } else {
            write!(output,
                        "{}",
                        format_field(&self.title, line_format.title_width, true))?;
        }
        write!(output, "{}", column_seperator)?;
        if line_format.status_width != 0 {
            write!(output,
                        "{}",
                        format_field(&format!("{:?}", self.status),
                                     line_format.status_width,
                                     false))?;
            write!(output, "{}", column_seperator)?;
        }
        writeln!(output,
                      "{}",
                      format_field(&localize_last_touched_string(&*self.last_touched)?,
                                   line_format.touched_width,
                                   false))?;
        if search_body {
            for l in self.body.lines() {
                writeln!(output, "\t{}", l)?;
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Status {
    Blank,
    Started,
    Urgent,
}

impl Encodable for Status {
    fn encode<S: rustc_serialize::Encoder>(&self,
                                           encoder: &mut S)
                                           -> ::std::result::Result<(), S::Error> {
        match *self {
            Status::Blank => {
                encoder.emit_enum("Status", |encoder| {
                    encoder.emit_enum_variant("", 0usize, 0usize, |_| Ok(()))
                })
            }
            Status::Started => {
                encoder.emit_enum("Status", |encoder| {
                    encoder.emit_enum_variant("Started", 1usize, 0usize, |_| Ok(()))
                })
            }
            Status::Urgent => {
                encoder.emit_enum("Status", |encoder| {
                    encoder.emit_enum_variant("Urgent", 2usize, 0usize, |_| Ok(()))
                })
            }
        }
    }
}

impl Decodable for Status {
    fn decode<D: ::rustc_serialize::Decoder>(decoder: &mut D)
                                             -> ::std::result::Result<Status, D::Error> {
        decoder.read_enum("Status", |decoder| {
            decoder.read_enum_variant(&["", "Started", "Urgent"], |_, i| {
                Ok(match i {
                    0usize => Status::Blank,
                    1usize => Status::Started,
                    2usize => Status::Urgent,
                    _ => panic!("internal error: entered unreachable code"),

                })
            })
        })
    }
}

impl fmt::Display for Status {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f,
               "{}",
               match *self {
                   Status::Blank => "",
                   Status::Started => "Started",
                   Status::Urgent => "Urgent",
               })
    }
}
