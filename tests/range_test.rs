use airlock::error::ProtocolError;
use airlock::range::{HttpRange, parse_range_header, resolve_range};

#[test]
fn test_single_range() {
    let header = "bytes=0-1024";
    let parsed = parse_range_header(header).expect("valid range");
    assert_eq!(
        parsed,
        HttpRange::Single {
            start: 0,
            end: Some(1024)
        }
    );

    let total_size = 5000;
    let resolved = resolve_range(&parsed, total_size).expect("resolves within bounds");
    assert_eq!(resolved.start, 0);
    assert_eq!(resolved.end, 1024);
    assert_eq!(resolved.length(), 1025);
    assert_eq!(resolved.total_size, 5000);
    assert_eq!(resolved.content_range_value(), "bytes 0-1024/5000");
}

#[test]
fn test_open_ended_range() {
    let header = "bytes=1024-";
    let parsed = parse_range_header(header).expect("valid open-ended range");
    assert_eq!(
        parsed,
        HttpRange::Single {
            start: 1024,
            end: None
        }
    );

    let total_size = 5000;
    let resolved = resolve_range(&parsed, total_size).expect("resolves to EOF");
    assert_eq!(resolved.start, 1024);
    assert_eq!(resolved.end, 4999);
    assert_eq!(resolved.length(), 3976);
    assert_eq!(resolved.content_range_value(), "bytes 1024-4999/5000");
}

#[test]
fn test_suffix_range() {
    let header = "bytes=-2048";
    let parsed = parse_range_header(header).expect("valid suffix range");
    assert_eq!(parsed, HttpRange::Suffix { length: 2048 });

    let total_size = 5000;
    let resolved = resolve_range(&parsed, total_size).expect("resolves suffix");
    assert_eq!(resolved.start, 5000 - 2048);
    assert_eq!(resolved.end, 4999);
    assert_eq!(resolved.length(), 2048);
    assert_eq!(resolved.content_range_value(), "bytes 2952-4999/5000");

    // Suffix larger than total size must clamp to entire resource (0..=total-1)
    let huge_suffix = HttpRange::Suffix { length: 10_000 };
    let clamped = resolve_range(&huge_suffix, total_size).expect("clamps to 0");
    assert_eq!(clamped.start, 0);
    assert_eq!(clamped.end, 4999);
    assert_eq!(clamped.length(), 5000);
}

#[test]
fn test_arithmetic_overflow_attack() {
    // Attack vector: bytes=0-18446744073709551615 (u64::MAX)
    let header = "bytes=0-18446744073709551615";
    let parsed = parse_range_header(header).expect("safe parse without overflow panic");
    assert_eq!(
        parsed,
        HttpRange::Single {
            start: 0,
            end: Some(u64::MAX)
        }
    );

    let total_size = 10_000_000; // 10 MB
    let resolved = resolve_range(&parsed, total_size).expect("safely clamped to total_size - 1");
    assert_eq!(resolved.start, 0);
    assert_eq!(resolved.end, 9_999_999);
    assert_eq!(resolved.length(), 10_000_000);
    assert_eq!(resolved.content_range_value(), "bytes 0-9999999/10000000");

    // Attack vector: start near u64::MAX
    let max_start = HttpRange::Single {
        start: u64::MAX - 10,
        end: Some(u64::MAX),
    };
    let err = resolve_range(&max_start, 5000).unwrap_err();
    match err {
        ProtocolError::RangeNotSatisfiable { start, total, .. } => {
            assert_eq!(start, u64::MAX - 10);
            assert_eq!(total, 5000);
        }
        _ => panic!("Expected RangeNotSatisfiable, got: {err:?}"),
    }
}

#[test]
fn test_multi_range_handling() {
    // RFC 9110: multi-range bytes=0-10,20-30
    let header = "bytes=0-10, 20-30, 100-200";
    let parsed = parse_range_header(header).expect("parses multi-range list");
    match &parsed {
        HttpRange::Multi(ranges) => {
            assert_eq!(ranges.len(), 3);
            assert_eq!(
                ranges[0],
                HttpRange::Single {
                    start: 0,
                    end: Some(10)
                }
            );
            assert_eq!(
                ranges[1],
                HttpRange::Single {
                    start: 20,
                    end: Some(30)
                }
            );
            assert_eq!(
                ranges[2],
                HttpRange::Single {
                    start: 100,
                    end: Some(200)
                }
            );
        }
        _ => panic!("Expected HttpRange::Multi, got: {parsed:?}"),
    }

    // Resolves to first satisfiable range
    let total_size = 500;
    let resolved = resolve_range(&parsed, total_size).expect("resolves first range");
    assert_eq!(resolved.start, 0);
    assert_eq!(resolved.end, 10);
    assert_eq!(resolved.length(), 11);
}

#[test]
fn test_out_of_bounds_rejection_416() {
    let total_size = 5000;

    // Start offset >= total_size
    let parsed = parse_range_header("bytes=999999999-").expect("valid syntax");
    let err = resolve_range(&parsed, total_size).unwrap_err();
    match err {
        ProtocolError::RangeNotSatisfiable { start, total, .. } => {
            assert_eq!(start, 999999999);
            assert_eq!(total, 5000);
        }
        _ => panic!("Expected RangeNotSatisfiable, got: {err:?}"),
    }

    // Start == total_size (0-indexed boundary condition)
    let parsed_exact = parse_range_header("bytes=5000-").expect("valid syntax");
    let err_exact = resolve_range(&parsed_exact, total_size).unwrap_err();
    assert!(matches!(
        err_exact,
        ProtocolError::RangeNotSatisfiable {
            start: 5000,
            total: 5000,
            ..
        }
    ));

    // Zero-byte total size
    let parsed_zero = parse_range_header("bytes=0-0").expect("valid syntax");
    let err_zero = resolve_range(&parsed_zero, 0).unwrap_err();
    assert!(matches!(
        err_zero,
        ProtocolError::RangeNotSatisfiable { total: 0, .. }
    ));
}

#[test]
fn test_invalid_syntax_rejection() {
    // Missing 'bytes=' prefix
    assert!(parse_range_header("characters=0-10").is_err());

    // Inverted range (start > end)
    assert!(parse_range_header("bytes=500-200").is_err());

    // Empty range
    assert!(parse_range_header("bytes=").is_err());
    assert!(parse_range_header("bytes=-").is_err());

    // Non-numeric garbage
    assert!(parse_range_header("bytes=abc-def").is_err());
}
