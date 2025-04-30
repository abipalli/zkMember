# ZKMember

ZKMember is a benchmark project designed to build and evaluate membership circuits using various SNARK protocols and finite fields. This project aims to provide a comprehensive comparison of different approaches to constructing and verifying membership proofs in zero-knowledge settings.

## Overview

The primary goal of ZKMember is to:

- Implement membership circuits using different SNARK protocols.
- Explore the use of various finite fields in these implementations.
- Benchmark the performance and efficiency of each approach.

## Features

- **Multiple SNARK Protocols**: Support for various SNARK protocols to provide a broad comparison.
- **Finite Fields**: Utilization of different finite fields to assess their impact on performance.
- **Benchmarking Tools**: Comprehensive tools to measure and compare the efficiency of each implementation.

## Installation
To quickly get started with the ZKMember CLI application, follow these steps:

1. Ensure you have Rust installed. If not, you can install it from [rust-lang.org](https://www.rust-lang.org/).
1. Clone the repository:
	```sh
	git clone https://github.com/abipalli/zkmember.git
	cd zkmember
	```

## Run Benchmarks

### groth16
To run the benchmarks for `groth16` circuits, run the following:

```sh
cargo bench --bench groth16
```

> `groth16` always uses circuit-specific constraints.

### marlin
To run the benchmarks for `marlin` circuits with **circuit-specific constraints**, run the following:

```sh
cargo bench --bench marlin
```

---

To run the benchmarks for `marlin` circuits with **universal constaraints**, simply add the `universal-constraints` feature:
```sh
cargo bench -F universal-constraints --bench marlin
```

<!--
## Run CLI

1. Run the CLI application:
	```sh
	cargo r
	```

This will start the ZKMember CLI application, allowing you to interact with the membership circuit.

### Example
```plaintext
> cargo r
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.07s
     Running `target/debug/zkmember`
✔ Choose an option · Register a new member
Enter ID: 123
Enter Email: 123@usc.edu
Number of Members: 1
root: 012c1650d5b36150f56050a7f7e8a1ed9d8d1b7cf14e0d35d60d5573ee2213030b

✔ Choose an option · Register a new member
Enter ID: 456
Enter Email: 456@usc.edu
Number of Members: 2
root: 01f57280c30a380d24950cf48160c22c5cda28b61d8ef1a24e92bae66372bf6b5a

✔ Choose an option · Generate a proof for a member
Enter ID: 123
root: f57280c30a380d24950cf48160c22c5cda28b61d8ef1a24e92bae66372bf6b5a
path: 85c81b129331338cd18c316ac058cb2924e433abc294b0b21553ad542ba47a1e00000000000000000000000000000000

✔ Choose an option · Exit
```
-->