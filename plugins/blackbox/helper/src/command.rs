//! Every program the root helper runs goes through here: with a hard timeout, so one stuck tool
//! (a hung `networksetup`, `profiles`, `plutil` on a FIFO) can never freeze a loop that protects
//! the Mac (security finding: no child command had a timeout).

use std::io::Read;
use std::process::{Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};

/// The default bound for a system tool the helper runs.
pub const TIMEOUT: Duration = Duration::from_secs(10);
/// The most output kept from one command (bytes, each stream).
const MAX_OUTPUT: u64 = 8 * 1024 * 1024;

fn collect<R: Read + Send + 'static>(stream: Option<R>) -> thread::JoinHandle<Vec<u8>> {
    thread::Builder::new().name("blackbox-netd-cmd-out".into()).spawn(move || {
        let mut buffer = Vec::new();
        if let Some(stream) = stream {
            let _ = stream.take(MAX_OUTPUT).read_to_end(&mut buffer);
        }
        buffer
    }).expect("a thread for a command's output")
}

/// Runs *command* to completion within *timeout* (stdin closed), like `Command::output`. On a
/// timeout the child — the helper's own — is killed and reaped, and an error is returned.
pub fn output(command: &mut Command, timeout: Duration) -> std::io::Result<Output> {
    output_with_input(command, None, timeout)
}

/// [`output`] with *input* written to the child's stdin (then closed).
pub fn output_with_input(command: &mut Command, input: Option<&[u8]>, timeout: Duration) -> std::io::Result<Output> {
    let stdin = if input.is_some() { Stdio::piped() } else { Stdio::null() };
    let mut child = command.stdin(stdin).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn()?;
    if let (Some(input), Some(mut pipe)) = (input.map(<[u8]>::to_vec), child.stdin.take()) {
        thread::Builder::new().name("blackbox-netd-cmd-in".into()).spawn(move || {
            use std::io::Write;
            let _ = pipe.write_all(&input);
        })?;
    }
    let out = collect(child.stdout.take());
    let err = collect(child.stderr.take());
    let started = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if started.elapsed() >= timeout {
            let _ = child.kill();
            let _ = child.wait();
            return Err(std::io::Error::new(std::io::ErrorKind::TimedOut, format!("timed out after {timeout:?}")));
        }
        thread::sleep(Duration::from_millis(10));
    };
    Ok(Output { status, stdout: out.join().unwrap_or_default(), stderr: err.join().unwrap_or_default() })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_command_that_hangs_is_stopped_at_the_timeout() {
        let started = Instant::now();
        let result = output(Command::new("/bin/sleep").arg("5"), Duration::from_millis(300));
        assert!(result.is_err() && started.elapsed() < Duration::from_secs(2), "{result:?}");
    }

    #[test]
    fn input_reaches_the_child() {
        let result = output_with_input(&mut Command::new("/bin/cat"), Some(b"abc"), TIMEOUT).unwrap();
        assert_eq!(result.stdout, b"abc");
    }

    #[test]
    fn a_quick_command_answers_with_its_output() {
        let result = output(Command::new("/bin/echo").arg("hello"), TIMEOUT).unwrap();
        assert!(result.status.success() && String::from_utf8_lossy(&result.stdout).trim() == "hello");
    }
}
