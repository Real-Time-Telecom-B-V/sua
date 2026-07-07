//! Memory-leak check.
//!
//! A counting global allocator tracks **live bytes** (allocated − freed), RSS
//! is too noisy (the OS/allocator retains freed pages), but live bytes are
//! exact, so a real leak shows up as monotonic growth. Two phases:
//!
//!   1. **codec**, encode + decode a CLDT and a DUNA message for many cycles
//!      (the common-header pack/unpack + TLV + GT/SSN/PC address copy path).
//!   2. **address**, encode + decode SUA addresses (GT + SSN + PC) on their own,
//!      over and over.
//!
//! Each phase asserts live bytes return to a flat baseline. Exits non-zero on a
//! leak. Driven by `scripts/mem_leak_test.sh`.
//!
//! Run: `cargo run --release --example leak_check`

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicI64, Ordering};

use sua::{GlobalTitle, SuaAddress, SuaMessage};

// ── Counting allocator ──────────────────────────────────────────────────────
static LIVE: AtomicI64 = AtomicI64::new(0);

struct Counting;
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        let p = System.alloc(l);
        if !p.is_null() {
            LIVE.fetch_add(l.size() as i64, Ordering::Relaxed);
        }
        p
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        System.dealloc(p, l);
        LIVE.fetch_sub(l.size() as i64, Ordering::Relaxed);
    }
    unsafe fn alloc_zeroed(&self, l: Layout) -> *mut u8 {
        let p = System.alloc_zeroed(l);
        if !p.is_null() {
            LIVE.fetch_add(l.size() as i64, Ordering::Relaxed);
        }
        p
    }
    unsafe fn realloc(&self, ptr: *mut u8, l: Layout, new_size: usize) -> *mut u8 {
        let p = System.realloc(ptr, l, new_size);
        if !p.is_null() {
            LIVE.fetch_add(new_size as i64 - l.size() as i64, Ordering::Relaxed);
        }
        p
    }
}

#[global_allocator]
static ALLOC: Counting = Counting;

fn live() -> i64 {
    LIVE.load(Ordering::Relaxed)
}

// ── Phase 1: codec workload ─────────────────────────────────────────────────
fn codec_cycle(iters: usize) {
    let source = SuaAddress::with_gt(GlobalTitle::e164("15550100"), Some(8));
    let dest = SuaAddress::with_gt(GlobalTitle::e164("15550142"), Some(6));
    let mut data = vec![0x62, 0x40, 0x48, 0x04];
    data.extend_from_slice(&[0xAB; 32]);
    let cldt = SuaMessage::cldt(42, 0, &source, &dest, 0, Some(15), data).expect("build cldt");
    let duna = SuaMessage::duna(Some(42), &[2000, 3000, 4000]);
    for _ in 0..iters {
        let c = cldt.encode();
        std::hint::black_box(SuaMessage::decode(&c).unwrap());
        let u = duna.encode();
        std::hint::black_box(SuaMessage::decode(&u).unwrap());
    }
}

// ── Phase 2: address churn ──────────────────────────────────────────────────
fn address_cycle(iters: usize) {
    for _ in 0..iters {
        let gt = SuaAddress::with_gt(GlobalTitle::e164("155501421"), Some(6));
        let enc = gt.encode().unwrap();
        std::hint::black_box(SuaAddress::decode(&enc).unwrap());
        let pc = SuaAddress::with_ssn_pc(8, 2000);
        let enc = pc.encode().unwrap();
        std::hint::black_box(SuaAddress::decode(&enc).unwrap());
    }
}

fn report(phase: &str, base: i64) -> i64 {
    let growth = live() - base;
    println!("  {phase}: live = {} bytes (Δ {:+})", live(), growth);
    growth
}

fn main() {
    const ITERS: usize = 200_000;
    const CYCLES: usize = 10;
    const BUDGET: i64 = 64 * 1024;

    // Phase 1: codec.
    println!("[codec] {CYCLES} x {ITERS} encode+decode round-trips (cldt + duna)");
    codec_cycle(ITERS); // warm up
    let codec_base = live();
    for c in 1..=CYCLES {
        codec_cycle(ITERS);
        report(&format!("cycle {c:>2}/{CYCLES}"), codec_base);
    }
    let codec_growth = live() - codec_base;

    // Phase 2: address.
    println!("\n[address] {CYCLES} x {ITERS} GT/SSN/PC address encode+decode");
    address_cycle(ITERS); // warm up
    let addr_base = live();
    for c in 1..=CYCLES {
        address_cycle(ITERS);
        report(&format!("cycle {c:>2}/{CYCLES}"), addr_base);
    }
    let addr_growth = live() - addr_base;

    // Verdict.
    println!();
    let mut ok = true;
    if codec_growth > BUDGET {
        eprintln!("FAIL: codec live bytes grew {codec_growth} (> {BUDGET})");
        ok = false;
    }
    if addr_growth > BUDGET {
        eprintln!("FAIL: address live bytes grew {addr_growth} (> {BUDGET})");
        ok = false;
    }
    if !ok {
        std::process::exit(1);
    }
    println!("PASS: codec Δ {codec_growth} ≤ {BUDGET}; address Δ {addr_growth} ≤ {BUDGET}");
}
