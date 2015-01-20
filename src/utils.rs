use std;
use std::io::{File, Open, ReadWrite,
              TempDir, Command, SeekSet};
use time::{get_time};
use std::os::{getenv};
use errors::{ThecaError, GenericError};
use std::io::process::{InheritFd};
use term;
use term::attr::Attr::{Bold};

pub use libc::{
    STDIN_FILENO,
    STDOUT_FILENO,
    STDERR_FILENO
};

// c calls for TIOCGWINSZ
mod c {
    extern crate libc;
    pub use self::libc::{
        c_int,
        c_ushort,
        c_ulong,
        STDOUT_FILENO
    };
    use std::mem::zeroed;
    pub struct Winsize {
        pub ws_row: c_ushort,
        pub ws_col: c_ushort
    }
    #[cfg(any(target_os = "linux", target_os = "android"))]
    static TIOCGWINSZ: c_ulong = 0x5413;
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    static TIOCGWINSZ: c_ulong = 0x40087468;
    extern {
        pub fn ioctl(fd: c_int, request: c_ulong, ...) -> c_int;
    }
    pub unsafe fn dimensions() -> Winsize {
        let mut window: Winsize = zeroed();
        ioctl(STDOUT_FILENO, TIOCGWINSZ, &mut window as *mut Winsize);
        window
    }
}

// unsafety wrapper
pub fn termsize() -> usize {
    let ws = unsafe {c::dimensions()};
    if ws.ws_col == 0 || ws.ws_row == 0 {
        0
    }
    else {
        ws.ws_col as usize
    }
}

pub fn drop_to_editor(contents: &String) -> Result<String, ThecaError> {
    // setup temporary directory
    let tmpdir = try!(TempDir::new("theca"));
    // setup temporary file to write/read
    let tmppath = tmpdir.path().join(get_time().sec.to_string());
    let mut tmpfile = try!(File::open_mode(&tmppath, Open, ReadWrite));
    try!(tmpfile.write_line(contents.as_slice()));
    // we now have a temp file, at `tmppath`, that contains `contents`
    // first we need to know which onqe
    let editor = match getenv("VISUAL") {
        Some(val) => val,
        None => {
            match getenv("EDITOR") {
                Some(val) => val,
                None => specific_fail!("neither $VISUAL nor $EDITOR is set.".to_string())
            }
        }
    };
    // lets start `editor` and edit the file at `tmppath`
    // first we need to set STDIN, STDOUT, and STDERR to those that theca is
    // currently using so we can display the editor
    let mut editor_command = Command::new(editor);
    editor_command.arg(tmppath.display().to_string());
    editor_command.stdin(InheritFd(STDIN_FILENO));
    editor_command.stdout(InheritFd(STDOUT_FILENO));
    editor_command.stderr(InheritFd(STDERR_FILENO));
    let editor_proc = editor_command.spawn();
    match try!(editor_proc).wait().is_ok() {
        true => {
            // finished editing, time to read `tmpfile` for the final output
            // seek to start of `tmpfile`
            try!(tmpfile.seek(0, SeekSet));
            Ok(try!(tmpfile.read_to_string()))
        }
        false => specific_fail!("The editor broke... I think".to_string())
    }
}

pub fn get_password() -> Result<String, ThecaError> {
    // should really turn off terminal echo...
    print!("Key: ");
    let mut stdin = std::io::stdio::stdin();
    // since this only reads one line of stdin it could still feasibly
    // be used with `-` to set note body?
    let key = try!(stdin.read_line());
    Ok(key.trim().to_string())
}

pub fn get_yn_input() -> Result<bool, ThecaError> {
    let mut stdin = std::io::stdio::stdin();
    let mut answer;
    let yes = vec!["y", "Y", "yes", "YES", "Yes"];
    let no = vec!["n", "N", "no", "NO", "No"];
    loop {
        print!("[y/n]# ");
        let mut input = try!(stdin.read_line());
        input = input.trim().to_string();
        match yes.iter().any(|n| n.as_slice() == input) {
            true => {
                answer = true;
                break;
            },
            false => {
                match no.iter().any(|n| n.as_slice() == input) {
                    true => {
                        answer = false;
                        break;
                    },
                    false => ()
                }
            }
        };
        println!("invalid input.");
    }
    Ok(answer)
}

pub fn pretty_line(bold: &str, plain: &String, color: bool) -> Result<(), ThecaError> {
    let mut t = match term::stdout() {
        Some(t) => t,
        None => specific_fail!("could not retrieve standard output.".to_string())
    };
    if color {try!(t.attr(Bold));}
    try!(write!(t, "{}", bold.to_string()));
    if color {try!(t.reset());}
    try!(write!(t, "{}", plain));
    Ok(())
}

pub fn format_field(value: &String, width: usize, truncate: bool) -> String {
    if value.len() > width && width > 3 && truncate {
        format!("{: <1$.1$}...", value, width-3)
    } else {
        format!("{: <1$.1$}", value, width)
    }
}
