# VerusHash Port Notes

This branch adds an experimental VerusHash / VRSC port to cpuminer-opt.

## Scope

- Adds `-a verus` and alias `verushash -> verus`.
- Imports the VerusHash hotpath under `algo/verus/`.
- Adds Verus-specific Luckpool-style Stratum notify, target and submit handling.
- Builds on ARM64 with `-march=armv8-a+crypto`.

## Build

Typical build flow:

```sh
./autogen.sh
./configure CFLAGS="-O3" CXXFLAGS="-O3"
make -j"$(nproc)"
```

Run `./cpuminer --help | grep -i verus` to verify that the algorithm is
registered.

## Status

This is an experimental source port intended for further correctness,
integration and performance work. Benchmark and live-mining results are kept
outside this repository.
