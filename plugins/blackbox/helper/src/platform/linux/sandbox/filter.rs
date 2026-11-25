//! The sandbox's seccomp filter, assembled as classic BPF: a short list of system calls an agent
//! never needs and that reach OUTSIDE its namespaces, each answered `EPERM`:
//!
//! * `ioctl(TIOCSTI)` / `ioctl(TIOCLINUX)` — typing into the person's terminal (a command pushed
//!   into the shell that started the agent runs outside the sandbox). Only the low 32 bits of the
//!   request are compared: the kernel ignores the rest, so setting high bits gains nothing;
//! * `keyctl`, `add_key`, `request_key` — the kernel keyrings are not namespaced (the person's
//!   session keyring holds tokens);
//! * `bpf`, `perf_event_open`, `userfaultfd` — kernel attack surface no coding agent uses.
//!
//! Every architecture a Linux build of the launcher can meet is covered: x86-64 and its 32-bit
//! i386 calls, arm64 and its 32-bit arm calls; x32 calls (the x86-64 ABI with 32-bit pointers,
//! which nothing ships) are refused whole. An unknown architecture passes untouched (fail-open:
//! the namespaces still hold).
//!
//! Pure: [`program`] returns the instructions; `system.rs` installs them. The tests run the
//! program in a small BPF interpreter, so they prove behaviour, not text.

/// One classic BPF instruction (`struct sock_filter`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Instruction {
    pub code: u16,
    pub jt: u8,
    pub jf: u8,
    pub k: u32,
}

const LD_W_ABS: u16 = 0x20; // BPF_LD | BPF_W | BPF_ABS
const JEQ_K: u16 = 0x15; // BPF_JMP | BPF_JEQ | BPF_K
const JGE_K: u16 = 0x35; // BPF_JMP | BPF_JGE | BPF_K
const RET_K: u16 = 0x06; // BPF_RET | BPF_K

pub const RET_ALLOW: u32 = 0x7fff_0000;
pub const RET_ERRNO: u32 = 0x0005_0000;
pub const EPERM: u32 = 1;

/// `struct seccomp_data` offsets: the call number, the architecture, the low word of argument 1.
const NR_AT: u32 = 0;
const ARCH_AT: u32 = 4;
const ARG1_LOW_AT: u32 = 16 + 8;

pub const AUDIT_ARCH_X86_64: u32 = 0xC000_003E;
pub const AUDIT_ARCH_I386: u32 = 0x4000_0003;
pub const AUDIT_ARCH_AARCH64: u32 = 0xC000_00B7;
pub const AUDIT_ARCH_ARM: u32 = 0x4000_0028;
/// x32 calls carry this bit in their number.
pub const X32_BIT: u32 = 0x4000_0000;

pub const TIOCSTI: u32 = 0x5412;
pub const TIOCLINUX: u32 = 0x541C;

/// One architecture's numbers: `ioctl`, then the calls refused outright
/// (`keyctl`, `add_key`, `request_key`, `bpf`, `perf_event_open`, `userfaultfd`).
pub struct Numbers {
    pub arch: u32,
    pub ioctl: u32,
    pub refused: [u32; 6],
}

pub const ARCHES: [Numbers; 4] = [
    Numbers { arch: AUDIT_ARCH_X86_64, ioctl: 16, refused: [250, 248, 249, 321, 298, 323] },
    Numbers { arch: AUDIT_ARCH_I386, ioctl: 54, refused: [288, 286, 287, 357, 336, 374] },
    Numbers { arch: AUDIT_ARCH_AARCH64, ioctl: 29, refused: [219, 217, 218, 280, 241, 282] },
    Numbers { arch: AUDIT_ARCH_ARM, ioctl: 54, refused: [311, 309, 310, 386, 364, 388] },
];

/// A tiny assembler: jumps name labels, resolved once every block is placed.
#[derive(Default)]
struct Assembler {
    code: Vec<(u16, Option<usize>, Option<usize>, u32)>,
    labels: Vec<Option<usize>>,
}

impl Assembler {
    fn label(&mut self) -> usize {
        self.labels.push(None);
        self.labels.len() - 1
    }
    fn place(&mut self, label: usize) {
        self.labels[label] = Some(self.code.len());
    }
    fn load(&mut self, at: u32) {
        self.code.push((LD_W_ABS, None, None, at));
    }
    /// If the accumulator equals *k* go to *to*, else fall through.
    fn jump_if(&mut self, code: u16, k: u32, to: usize) {
        self.code.push((code, Some(to), None, k));
    }
    fn ret(&mut self, k: u32) {
        self.code.push((RET_K, None, None, k));
    }
    fn finish(self) -> Vec<Instruction> {
        self.code.iter().enumerate().map(|(index, (code, jt, jf, k))| {
            let offset = |label: &Option<usize>| -> u8 {
                label.map(|l| {
                    let target = self.labels[l].expect("every label placed");
                    u8::try_from(target - index - 1).expect("the filter's jumps stay short")
                }).unwrap_or(0)
            };
            Instruction { code: *code, jt: offset(jt), jf: offset(jf), k: *k }
        }).collect()
    }
}

/// The whole filter (see the module doc).
pub fn program() -> Vec<Instruction> {
    let mut asm = Assembler::default();
    let refuse = asm.label();
    let blocks: Vec<usize> = ARCHES.iter().map(|_| asm.label()).collect();
    asm.load(ARCH_AT);
    for (numbers, block) in ARCHES.iter().zip(&blocks) {
        asm.jump_if(JEQ_K, numbers.arch, *block);
    }
    asm.ret(RET_ALLOW);
    for (numbers, block) in ARCHES.iter().zip(&blocks) {
        asm.place(*block);
        asm.load(NR_AT);
        if numbers.arch == AUDIT_ARCH_X86_64 {
            asm.jump_if(JGE_K, X32_BIT, refuse);
        }
        for number in numbers.refused {
            asm.jump_if(JEQ_K, number, refuse);
        }
        let ioctl = asm.label();
        asm.jump_if(JEQ_K, numbers.ioctl, ioctl);
        asm.ret(RET_ALLOW);
        asm.place(ioctl);
        asm.load(ARG1_LOW_AT);
        asm.jump_if(JEQ_K, TIOCSTI, refuse);
        asm.jump_if(JEQ_K, TIOCLINUX, refuse);
        asm.ret(RET_ALLOW);
    }
    asm.place(refuse);
    asm.ret(RET_ERRNO | EPERM);
    asm.finish()
}

/// Runs *program* on one call (a test's interpreter of the instructions [`program`] uses).
#[cfg(test)]
fn run(program: &[Instruction], arch: u32, nr: u32, arg1: u64) -> u32 {
    let mut data = [0u8; 64];
    data[0..4].copy_from_slice(&nr.to_le_bytes());
    data[4..8].copy_from_slice(&arch.to_le_bytes());
    data[24..32].copy_from_slice(&arg1.to_le_bytes());
    let (mut pc, mut acc) = (0usize, 0u32);
    loop {
        let op = program[pc];
        pc += 1;
        match op.code {
            LD_W_ABS => {
                let at = op.k as usize;
                acc = u32::from_le_bytes(data[at..at + 4].try_into().unwrap());
            }
            JEQ_K => pc += usize::from(if acc == op.k { op.jt } else { op.jf }),
            JGE_K => pc += usize::from(if acc >= op.k { op.jt } else { op.jf }),
            RET_K => return op.k,
            other => panic!("unexpected instruction {other:#x}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const REFUSED: u32 = RET_ERRNO | EPERM;

    #[test]
    fn terminal_injection_is_refused_on_every_architecture_and_other_ioctls_pass() {
        let filter = program();
        for numbers in &ARCHES {
            assert_eq!(run(&filter, numbers.arch, numbers.ioctl, u64::from(TIOCSTI)), REFUSED);
            assert_eq!(run(&filter, numbers.arch, numbers.ioctl, u64::from(TIOCLINUX)), REFUSED);
            assert_eq!(run(&filter, numbers.arch, numbers.ioctl, 0xFFFF_FFFF_0000_0000 | u64::from(TIOCSTI)), REFUSED,
                       "high bits the kernel ignores change nothing");
            assert_eq!(run(&filter, numbers.arch, numbers.ioctl, 0x5413), RET_ALLOW, "TIOCGWINSZ (window size) passes");
        }
    }

    #[test]
    fn keyrings_bpf_perf_and_userfaultfd_are_refused_and_ordinary_calls_pass() {
        let filter = program();
        for numbers in &ARCHES {
            for number in numbers.refused {
                assert_eq!(run(&filter, numbers.arch, number, 0), REFUSED, "arch {:#x} call {number}", numbers.arch);
            }
            assert_eq!(run(&filter, numbers.arch, 1, 0), RET_ALLOW);
            assert_eq!(run(&filter, numbers.arch, 59, 0), RET_ALLOW);
        }
    }

    #[test]
    fn x32_calls_are_refused_and_an_unknown_architecture_passes() {
        let filter = program();
        assert_eq!(run(&filter, AUDIT_ARCH_X86_64, X32_BIT | 16, u64::from(TIOCSTI)), REFUSED);
        assert_eq!(run(&filter, AUDIT_ARCH_X86_64, X32_BIT | 1, 0), REFUSED);
        assert_eq!(run(&filter, 0xC000_00F3, 16, u64::from(TIOCSTI)), RET_ALLOW, "riscv64: untouched (fail-open)");
    }

    #[test]
    fn the_filter_fits_the_kernel_limit() {
        assert!(program().len() < 4096);
    }
}
