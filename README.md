## KZG Commitment in Rust

This is a Rust implementation of the KZG commitment scheme. There are two main modules:
1. `kzg.rs` implements the basic polynomial commitment that allows both opening at a single point and also batch opening (sometimes known as multi proof).
2. `asvc.rs` implements a vector commitment scheme based on [this paper](https://eprint.iacr.org/2020/527.pdf). It supports proving vector position and also aggregating multiple KZG proofs into a single proof.

### Getting Started

To run the tests, use `cargo run`.

### Disclaimer

This code is unaudited and under construction. This is experimental software and is provided on an "as is" and "as available" basis and may not work at all. It should not be used in production.