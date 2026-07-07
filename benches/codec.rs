//! Codec micro-benchmarks: SUA message encode/decode across the message classes.
//!
//! Run with `cargo bench`. Numbers feed the README "Performance" table.
//!
//! All fixtures are built from the public API (RFC 3868 wire layout), so the
//! benches measure exactly the work this crate does, common-header pack/unpack,
//! TLV parameter encode/decode, and the GT/SSN/PC address copy path, with no I/O.
//! Synthetic data only (fictional +1-555 global titles, decimal point codes).

use criterion::{criterion_group, criterion_main, BatchSize, Criterion, Throughput};
use sua::{GlobalTitle, SuaAddress, SuaMessage};

/// A representative SCCP-user payload (synthetic: a short TCAP-ish body). Length
/// is what matters for the copy path, not the contents.
fn sample_data() -> Vec<u8> {
    let mut d = vec![0x62, 0x40, 0x48, 0x04, 0x00, 0x00, 0x00, 0x01];
    d.extend_from_slice(&[0xAB; 24]);
    d
}

fn bench_codec(c: &mut Criterion) {
    // Connectionless: a CLDT carrying the SCCP user between two GT+SSN addresses.
    let source = SuaAddress::with_gt(GlobalTitle::e164("15550100"), Some(8));
    let dest = SuaAddress::with_gt(GlobalTitle::e164("15550142"), Some(6));
    let cldt =
        SuaMessage::cldt(42, 0, &source, &dest, 0, Some(15), sample_data()).expect("build cldt");

    // SNM: a DUNA advertising three affected point codes.
    let duna = SuaMessage::duna(Some(42), &[2000, 3000, 4000]);

    // ASPSM: an ASP-UP with an ASP Identifier + Info String.
    let aspup = SuaMessage::asp_up(Some(1), Some("bench"));

    let cldt_bytes = cldt.encode();
    let duna_bytes = duna.encode();
    let aspup_bytes = aspup.encode();

    let mut g = c.benchmark_group("codec");
    g.throughput(Throughput::Elements(1));

    g.bench_function("cldt/decode", |b| {
        b.iter(|| SuaMessage::decode(&cldt_bytes).unwrap())
    });
    g.bench_function("cldt/encode", |b| {
        b.iter_batched(|| cldt.clone(), |m| m.encode(), BatchSize::SmallInput)
    });
    g.bench_function("duna/decode", |b| {
        b.iter(|| SuaMessage::decode(&duna_bytes).unwrap())
    });
    g.bench_function("aspup/decode", |b| {
        b.iter(|| SuaMessage::decode(&aspup_bytes).unwrap())
    });

    // The full extraction path a CLDT consumer runs: decode + pull both
    // addresses and the data.
    g.bench_function("cldt/decode+addresses", |b| {
        b.iter(|| {
            let m = SuaMessage::decode(&cldt_bytes).unwrap();
            let _ = m.source_address().unwrap();
            let _ = m.destination_address().unwrap();
            m.data().map(|d| d.len())
        })
    });
    g.finish();
}

criterion_group!(benches, bench_codec);
criterion_main!(benches);
