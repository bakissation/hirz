//! Examples from RFC 8949 Appendix A that fall inside the supported subset, plus the
//! Appendix A items this decoder must reject. Copyright (c) 2020 IETF Trust and the persons
//! identified as the document authors (https://trustee.ietf.org/license-info).
#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

mod common;

use common::hex;
use hirz_proto::Error;
use hirz_proto::cbor::{self, Limits, MapBuilder, Value};

fn text(s: &str) -> Value {
    Value::from(s)
}

fn arr(items: Vec<Value>) -> Value {
    Value::Array(items)
}

#[test]
fn supported_examples_round_trip() {
    let cases: Vec<(&str, Value)> = vec![
        ("00", Value::Unsigned(0)),
        ("01", Value::Unsigned(1)),
        ("0a", Value::Unsigned(10)),
        ("17", Value::Unsigned(23)),
        ("1818", Value::Unsigned(24)),
        ("1819", Value::Unsigned(25)),
        ("1864", Value::Unsigned(100)),
        ("1903e8", Value::Unsigned(1000)),
        ("1a000f4240", Value::Unsigned(1_000_000)),
        ("1b000000e8d4a51000", Value::Unsigned(1_000_000_000_000)),
        ("1bffffffffffffffff", Value::Unsigned(u64::MAX)),
        ("3bffffffffffffffff", Value::Negative(u64::MAX)),
        ("20", Value::int(-1)),
        ("29", Value::int(-10)),
        ("3863", Value::int(-100)),
        ("3903e7", Value::int(-1000)),
        ("f4", Value::Bool(false)),
        ("f5", Value::Bool(true)),
        ("f6", Value::Null),
        ("40", Value::Bytes(vec![])),
        ("4401020304", Value::Bytes(vec![1, 2, 3, 4])),
        ("60", text("")),
        ("6161", text("a")),
        ("6449455446", text("IETF")),
        ("62225c", text("\"\\")),
        ("62c3bc", text("\u{fc}")),
        ("63e6b0b4", text("\u{6c34}")),
        ("64f0908591", text("\u{10151}")),
        ("80", arr(vec![])),
        (
            "83010203",
            arr(vec![Value::int(1), Value::int(2), Value::int(3)]),
        ),
        (
            "8301820203820405",
            arr(vec![
                Value::int(1),
                arr(vec![Value::int(2), Value::int(3)]),
                arr(vec![Value::int(4), Value::int(5)]),
            ]),
        ),
        (
            "98190102030405060708090a0b0c0d0e0f101112131415161718181819",
            arr((1..=25u64).map(Value::Unsigned).collect()),
        ),
        ("a0", Value::Map(vec![])),
        ("a201020304", MapBuilder::new().int(1, 2).int(3, 4).build()),
        (
            "a26161016162820203",
            MapBuilder::new()
                .text("a", 1)
                .text("b", arr(vec![Value::int(2), Value::int(3)]))
                .build(),
        ),
        (
            "826161a161626163",
            arr(vec![text("a"), MapBuilder::new().text("b", "c").build()]),
        ),
        (
            "a56161614161626142616361436164614461656145",
            MapBuilder::new()
                .text("a", "A")
                .text("b", "B")
                .text("c", "C")
                .text("d", "D")
                .text("e", "E")
                .build(),
        ),
    ];
    for (h, expected) in cases {
        let bytes = hex(h);
        let decoded = cbor::decode(&bytes, &Limits::default()).unwrap();
        assert_eq!(decoded, expected, "{h}");
        assert_eq!(cbor::encode(&expected).unwrap(), bytes, "{h}");
        for len in 0..bytes.len() {
            assert!(
                cbor::decode(&bytes[..len], &Limits::default()).is_err(),
                "{h}"
            );
        }
    }
    assert_eq!(
        cbor::decode(&hex("3bffffffffffffffff"), &Limits::default())
            .unwrap()
            .as_i128(),
        Some(-18_446_744_073_709_551_616)
    );
}

#[test]
fn unsupported_examples_are_rejected() {
    let unsupported = [
        "f90000",
        "f98000",
        "f93c00",
        "fb3ff199999999999a",
        "f93e00",
        "f97bff",
        "fa47c35000",
        "fa7f7fffff",
        "fb7e37e43c8800759c",
        "f90001",
        "f90400",
        "f9c400",
        "fbc010666666666666",
        "f97c00",
        "f97e00",
        "f9fc00",
        "fa7f800000",
        "fa7fc00000",
        "faff800000",
        "fb7ff0000000000000",
        "fb7ff8000000000000",
        "fbfff0000000000000",
        "f0",
        "f7",
        "f8ff",
        "c074323031332d30332d32315432303a30343a30305a",
        "c11a514b67b0",
        "c1fb41d452d9ec200000",
        "d74401020304",
        "d818456449455446",
        "d82076687474703a2f2f7777772e6578616d706c652e636f6d",
        "c249010000000000000000",
        "c349010000000000000000",
        "5f42010243030405ff",
        "7f657374726561646d696e67ff",
        "9fff",
        "9f018202039f0405ffff",
        "9f01820203820405ff",
        "83018202039f0405ff",
        "83019f0203ff820405",
        "9f0102030405060708090a0b0c0d0e0f101112131415161718181819ff",
        "bf61610161629f0203ffff",
        "826161bf61626163ff",
        "bf6346756ef563416d7421ff",
    ];
    for h in unsupported {
        assert_eq!(
            cbor::decode(&hex(h), &Limits::default()),
            Err(Error::Unsupported),
            "{h}"
        );
    }
    for h in ["ff", "1c", "3d", "5e", "7c", "9d", "be", "fc", "fd", "fe"] {
        assert!(cbor::decode(&hex(h), &Limits::default()).is_err(), "{h}");
    }
}

#[test]
fn appendix_maps_with_non_text_keys() {
    // {1: 2, 3: 4} is fine; arrays and maps as keys are outside the subset.
    assert!(cbor::decode(&hex("a201020304"), &Limits::default()).is_ok());
    assert_eq!(
        cbor::decode(&hex("a1820102f6"), &Limits::default()),
        Err(Error::Unsupported)
    );
}
