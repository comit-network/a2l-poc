# A2L PoC

A proof of concept of the A2L protocol on top of Bitcoin in pretty good (YMMV) Rust.

## Achievements

- We demonstrate the A2L protocol on top of today's Bitcoin without the need for Schnorr signatures or MP-ECDSA including refund/abort scenarios.
- We implement an extension of the A2L protocol that prevents a DoS attack against the tumbler by forcing the sender to lock up funds first. 
- We implement correct fee handling for all transaction and test the generated transaction against Bitcoin Core 0.19.1.

## Implementation details

- Instead of 2p-ECDSA, we use 1p-ECDSA adaptor signatures in a 2-out-of-2 multi-signature script using Miniscript [1].
- The PoC focuses on clarity, consistency and, where possible, parity with the paper at the expense of raw performance.

## Benchmark results

### Computation time

These are created with the following command: `cargo test --test dry protocol_computation_time --release -- --exact --nocapture`

| Receiving message                |     Mean  | Standard deviation |
| ---------------------------------|----------|------------------- |
| puzzle_solver::Message0          |   2.30ms |           383.00µs |
| puzzle_solver::Message1          | 534.00µs |            56.00µs |
| puzzle_solver::FundTransaction   |   1.32ms |            68.00µs |
| puzzle_solver::Message2          |   2.04ms |           206.00µs |
| puzzle_solver::Message3          |   0.00ns |             0.00ns |
| puzzle_promise::Message0         | 592.76ms |            26.39ms |
| puzzle_promise::Message1         | 378.80ms |            21.30ms |
| puzzle_promise::Message2         |   1.33ms |           139.00µs |
| puzzle_promise::Message3         | 105.41ms |             5.46ms |
| puzzle_promise::Message4         | 102.77ms |             5.26ms |
| puzzle_solver::Message4          | 132.39ms |             8.61ms |
| puzzle_solver::Message5          | 970.00µs |           130.00µs |
| puzzle_solver::Message6          | 622.00µs |            95.00µs |
| puzzle_solver::RedeemTransaction | 767.00µs |           111.00µs |
| puzzle_solver::Message7          | 603.00µs |            98.00µs |
| Full protocol                    |    1.32s |            35.81ms |

### Bandwidth

Total bandwidth using CBOR encoding is 7988 bytes and does not exceed maximum expected bandwidth of 8000 bytes.

You can check this yourself using the following command: `cargo test --test dry protocol_bandwidth --release -- --exact --nocapture`.
The bandwidth used can vary slightly from run to run because some signatures vary in size.

### Blockchain footprint

Total weight of both redeem transactions is 1093 and does not exceed maximum expected weight of 1095.

You can check this yourself using the following command: `cargo test --test dry redeem_transaction_size --release -- --exact --nocapture`.
The total weight can vary slightly from run to run because some signatures vary in size.

## Limitations

### Class group

The class group generated for the homomorphic encryption scheme HSM-CL is not statically encoded but randomly regenerated upon startup.
This is due to a limitation in the implementation present in https://github.com/KZen-networks/class (this PoC depends on a fork of this library).

This is fine for the PoC because everything is executed within a single process but breaks for any real-world usage because every party would generate a different class group and hence the proofs would not be verifiable.

### Single threaded

The tests can only be executed on a single thread (`cargo test -- --test-threads=1`) due to non-thread safe usage of the PARI library in https://github.com/KZen-networks/class.

## References

- [1] Miniscript, https://github.com/apoelstra/rust-miniscript
