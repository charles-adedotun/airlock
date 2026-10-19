use airlock::LiveRingBuffer;
use bytes::Bytes;
use criterion::{BenchmarkId, Criterion, Throughput, black_box, criterion_group, criterion_main};

fn bench_ring_writes(c: &mut Criterion) {
    let mut group = c.benchmark_group("ring_buffer_writes");

    // Benchmark realistic media chunk sizes:
    // 188 B (single MPEG-TS packet), 64 KiB (network read chunk), 256 KiB (I/O block)
    for size in [188, 64 * 1024, 256 * 1024] {
        let chunk = Bytes::from(vec![0x47u8; size]);
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::new("push", size), &chunk, |b, data| {
            let ring = LiveRingBuffer::new(64 * 1024 * 1024); // 64 MiB ring capacity
            b.iter(|| {
                let _ = black_box(ring.push(black_box(data.clone()), false));
            });
        });
    }
    group.finish();
}

fn bench_ring_reads(c: &mut Criterion) {
    let mut group = c.benchmark_group("ring_buffer_reads");
    let chunk_size = 64 * 1024;
    let chunk = Bytes::from(vec![0x47u8; chunk_size]);
    let ring = LiveRingBuffer::new(64 * 1024 * 1024);

    // Pre-populate with 500 chunks
    for i in 0..500 {
        let is_kf = i % 30 == 0;
        let _ = ring.push(chunk.clone(), is_kf);
    }

    group.throughput(Throughput::Bytes((10 * chunk_size) as u64));
    group.bench_function("read_10_chunks", |b| {
        b.iter(|| {
            let _ = black_box(ring.read_from(black_box(250), 10));
        });
    });

    group.bench_function("latest_keyframe_lookup", |b| {
        b.iter(|| {
            let _ = black_box(ring.latest_keyframe_sequence());
        });
    });

    group.finish();
}

criterion_group!(benches, bench_ring_writes, bench_ring_reads);
criterion_main!(benches);
