//! File Shield's real-time file events on macOS: an FSEvents stream over a set of paths
//! (`native/fsevents.c`), each change handed to a channel as a [`Change`]. Observing only: it reads
//! no file and changes nothing. [`super::super::file_shield`] decides what to watch and reports.

use std::ffi::{c_void, CStr, CString};
use std::os::raw::c_char;
use std::sync::mpsc::Sender;
use std::sync::Mutex;

/// How long FSEvents may gather changes before delivering them (seconds).
const LATENCY_SECONDS: f64 = 0.2;

// FSEvents flags (CoreServices FSEvents.h), the ones that say what happened.
const ITEM_CREATED: u32 = 0x0000_0100;
const ITEM_REMOVED: u32 = 0x0000_0200;
const ITEM_INODE_META: u32 = 0x0000_0400;
const ITEM_RENAMED: u32 = 0x0000_0800;
const ITEM_MODIFIED: u32 = 0x0000_1000;
const ITEM_XATTR: u32 = 0x0000_8000;
const ROOT_CHANGED: u32 = 0x0000_0020;

extern "C" {
    fn bb_fs_watch_start(paths: *const *const c_char, count: i32, latency: f64, context: *mut c_void) -> *mut c_void;
    fn bb_fs_watch_stop(handle: *mut c_void);
}

/// One change: the absolute *path* and what happened (*kind*: created, removed, renamed, modified
/// or changed from FSEvents; `denied` from the sandbox's log, [`super::sandbox_denials`]). *program*
/// is the program the log names for a denial ("" from FSEvents, which can not say).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Change {
    pub path: String,
    pub kind: &'static str,
    pub program: String,
    /// The refused process's pid as the log names it (0 from FSEvents): the plugin finds the agent
    /// instance it belongs to by its ancestry while it may still run (KI-598).
    pub pid: u32,
}

/// What a set of FSEvents flags says happened (the most telling first).
pub fn kind_of(flags: u32) -> &'static str {
    if flags & ITEM_REMOVED != 0 || flags & ROOT_CHANGED != 0 {
        "removed"
    } else if flags & ITEM_RENAMED != 0 {
        "renamed"
    } else if flags & ITEM_CREATED != 0 {
        "created"
    } else if flags & (ITEM_MODIFIED | ITEM_INODE_META | ITEM_XATTR) != 0 {
        "modified"
    } else {
        "changed"
    }
}

/// Where the C callback sends: the channel of the watch it belongs to (boxed, so its address is stable).
struct Context {
    sender: Mutex<Sender<Change>>,
}

#[no_mangle]
extern "C" fn bb_fs_event(path: *const c_char, flags: u32, context: *mut c_void) {
    if path.is_null() || context.is_null() {
        return;
    }
    // SAFETY: *context* is the Box<Context> a live Watch owns (stopped before it is dropped), and
    // FSEvents hands a NUL-terminated path valid for the call.
    let context = unsafe { &*(context as *const Context) };
    let path = unsafe { CStr::from_ptr(path) }.to_string_lossy().into_owned();
    if let Ok(sender) = context.sender.lock() {
        let _ = sender.send(Change { path, kind: kind_of(flags), program: String::new(), pid: 0 });
    }
}

/// A running FSEvents stream; stops when dropped.
pub struct Watch {
    handle: *mut c_void,
    _context: Box<Context>,
}

// SAFETY: the handle is used only by start/stop, which FSEvents allows from any thread.
unsafe impl Send for Watch {}

impl Watch {
    /// Starts watching *paths* (absolute); None when FSEvents could not start a stream.
    pub fn start(paths: &[String], sender: Sender<Change>) -> Option<Watch> {
        let owned: Vec<CString> = paths.iter().filter_map(|p| CString::new(p.as_str()).ok()).collect();
        if owned.is_empty() {
            return None;
        }
        let pointers: Vec<*const c_char> = owned.iter().map(|p| p.as_ptr()).collect();
        let context = Box::new(Context { sender: Mutex::new(sender) });
        let raw = &*context as *const Context as *mut c_void;
        // SAFETY: the pointers outlive the call (FSEvents copies the paths); *raw* lives as long as Watch.
        let handle = unsafe { bb_fs_watch_start(pointers.as_ptr(), pointers.len() as i32, LATENCY_SECONDS, raw) };
        (!handle.is_null()).then(|| Watch { handle, _context: context })
    }
}

impl Drop for Watch {
    fn drop(&mut self) {
        // SAFETY: *handle* came from bb_fs_watch_start and is stopped exactly once; after it returns
        // no callback can reach the context, which is dropped next.
        unsafe { bb_fs_watch_stop(self.handle) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc::channel;
    use std::time::{Duration, Instant};

    #[test]
    fn flags_say_what_happened() {
        assert_eq!(kind_of(ITEM_CREATED), "created");
        assert_eq!(kind_of(ITEM_CREATED | ITEM_MODIFIED), "created");
        assert_eq!(kind_of(ITEM_REMOVED | ITEM_CREATED), "removed");
        assert_eq!(kind_of(ITEM_RENAMED), "renamed");
        assert_eq!(kind_of(ITEM_XATTR), "modified");
        assert_eq!(kind_of(0), "changed");
    }

    #[test]
    fn a_new_file_in_a_watched_folder_is_reported_within_seconds() {
        let folder = std::env::temp_dir().join(format!("bb-file-watch-{}", std::process::id()));
        std::fs::create_dir_all(&folder).unwrap();
        let folder = folder.canonicalize().unwrap();
        let (sender, receiver) = channel();
        let watch = Watch::start(&[folder.to_string_lossy().into_owned()], sender).expect("an FSEvents stream");
        std::thread::sleep(Duration::from_millis(300));   // FSEvents reports from the stream's start onwards
        let file = folder.join("arrived.txt");
        std::fs::write(&file, b"x").unwrap();
        let started = Instant::now();
        let mut seen = None;
        while started.elapsed() < Duration::from_secs(10) {
            if let Ok(change) = receiver.recv_timeout(Duration::from_millis(500)) {
                if change.path.ends_with("arrived.txt") {
                    seen = Some(change);
                    break;
                }
            }
        }
        drop(watch);
        let _ = std::fs::remove_dir_all(&folder);
        let change = seen.expect("the new file was reported");
        assert!(["created", "modified"].contains(&change.kind), "{change:?}");
    }
}
