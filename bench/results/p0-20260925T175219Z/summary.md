# zkship P0 results

Intel(R) Core(TM) i7-14700K, 28 logical CPUs, governor powersave, Linux 7.0.0-31-generic; rustc 1.89.0 (29483883e 2025-08-04); commit `41dbd47451ab`; single-threaded runs pinned with `taskset -c 4`. Load at start: 1.39.

## Message sizes (bytes)

| message | cryptographic payload | message (with tag) | signed frame |
|---|---|---|---|
| setup_standard | 19488 | 19488 | 19630 |
| setup_no-touch | 20544 | 20544 | 20686 |
| hello_unframed | 0 | 162 | 162 |
| coin_message | 32 | 32 | 174 |
| shot | 1 | 1 | 143 |
| answer_miss | 32 | 33 | 175 |
| answer_hit_unsunk5 | 576 | 577 | 719 |
| answer_hit_unsunk4 | 576 | 577 | 719 |
| answer_hit_unsunk3 | 576 | 577 | 719 |
| answer_hit_unsunk2 | 512 | 513 | 655 |
| answer_hit_unsunk1 | 448 | 449 | 591 |
| answer_sunk_len5 | 192 | 199 | 341 |
| answer_sunk_len4 | 160 | 166 | 308 |
| answer_sunk_len3 | 128 | 133 | 275 |
| answer_sunk_len2 | 96 | 100 | 242 |

Cryptographic payload is what the abstract counts: group elements and scalars (for a sink announcement, not the ship index and cell list). Messages add a 1-byte tag; frames add a 78-byte header and a 64-byte Ed25519 signature. The Hello precedes framing.

## Per-operation timings (ms, median / p95)

| operation | rules | case | bytes | n | median | p95 |
|---|---|---|---|---|---|---|
| setup_prove | standard | - | 19488 | 200 | 76.8 | 79.7 |
| setup_encode | standard | - | 19488 | 200 | 1.48 | 1.52 |
| setup_decode | standard | - | 19488 | 200 | 1.51 | 1.54 |
| setup_verify | standard | - | 19488 | 200 | 13.4 | 13.7 |
| setup_decode+verify | standard | - | 19488 | 200 | 15.0 | 15.3 |
| setup_prove | no-touch | - | 20544 | 200 | 351 | 372 |
| setup_encode | no-touch | - | 20544 | 200 | 1.57 | 1.68 |
| setup_decode | no-touch | - | 20544 | 200 | 1.60 | 1.70 |
| setup_verify | no-touch | - | 20544 | 200 | 44.4 | 47.4 |
| setup_decode+verify | no-touch | - | 20544 | 200 | 46.0 | 49.1 |
| answer_produce | standard | miss | 33 | 1000 | 0.1&nbsp;µs | 0.1&nbsp;µs |
| answer_decode | standard | miss | 33 | 1000 | 0.1&nbsp;µs | 0.1&nbsp;µs |
| answer_verify | standard | miss | 33 | 1000 | 18.0&nbsp;µs | 18.5&nbsp;µs |
| answer_produce | standard | hit_unsunk5 | 577 | 1000 | 1.49 | 1.59 |
| answer_decode | standard | hit_unsunk5 | 577 | 1000 | 33.1&nbsp;µs | 35.6&nbsp;µs |
| answer_verify | standard | hit_unsunk5 | 577 | 1000 | 0.41 | 0.44 |
| answer_produce | standard | hit_unsunk4 | 577 | 1000 | 1.49 | 1.58 |
| answer_decode | standard | hit_unsunk4 | 577 | 1000 | 33.6&nbsp;µs | 35.9&nbsp;µs |
| answer_verify | standard | hit_unsunk4 | 577 | 1000 | 0.39 | 0.41 |
| answer_produce | standard | hit_unsunk3 | 577 | 1000 | 1.47 | 1.62 |
| answer_decode | standard | hit_unsunk3 | 577 | 1000 | 33.7&nbsp;µs | 37.4&nbsp;µs |
| answer_verify | standard | hit_unsunk3 | 577 | 1000 | 0.36 | 0.40 |
| answer_produce | standard | hit_unsunk2 | 513 | 1000 | 0.84 | 0.93 |
| answer_decode | standard | hit_unsunk2 | 513 | 1000 | 28.2&nbsp;µs | 31.1&nbsp;µs |
| answer_verify | standard | hit_unsunk2 | 513 | 1000 | 0.25 | 0.28 |
| answer_produce | standard | hit_unsunk1 | 449 | 1000 | 0.50 | 0.55 |
| answer_decode | standard | hit_unsunk1 | 449 | 1000 | 23.1&nbsp;µs | 25.6&nbsp;µs |
| answer_verify | standard | hit_unsunk1 | 449 | 1000 | 0.18 | 0.20 |
| answer_produce | standard | sunk_len5 | 199 | 1000 | 0.3&nbsp;µs | 0.4&nbsp;µs |
| answer_decode | standard | sunk_len5 | 199 | 1000 | 0.4&nbsp;µs | 0.4&nbsp;µs |
| answer_verify | standard | sunk_len5 | 199 | 1000 | 0.11 | 0.11 |
| answer_produce | standard | sunk_len4 | 166 | 1000 | 0.3&nbsp;µs | 0.4&nbsp;µs |
| answer_decode | standard | sunk_len4 | 166 | 1000 | 0.3&nbsp;µs | 0.4&nbsp;µs |
| answer_verify | standard | sunk_len4 | 166 | 1000 | 90.6&nbsp;µs | 95.0&nbsp;µs |
| answer_produce | standard | sunk_len3 | 133 | 1000 | 0.3&nbsp;µs | 0.3&nbsp;µs |
| answer_decode | standard | sunk_len3 | 133 | 1000 | 0.3&nbsp;µs | 0.3&nbsp;µs |
| answer_verify | standard | sunk_len3 | 133 | 1000 | 72.5&nbsp;µs | 75.5&nbsp;µs |
| answer_produce | standard | sunk_len2 | 100 | 1000 | 0.3&nbsp;µs | 0.3&nbsp;µs |
| answer_decode | standard | sunk_len2 | 100 | 1000 | 0.2&nbsp;µs | 0.2&nbsp;µs |
| answer_verify | standard | sunk_len2 | 100 | 1000 | 53.5&nbsp;µs | 55.5&nbsp;µs |
| setup_reject | standard | early_length | 19488 | 200 | 1.58 | 1.67 |
| setup_reject | standard | late_bit_proof | 19488 | 200 | 14.2 | 16.3 |
| answer_reject | standard | false_miss | 33 | 1000 | 17.7&nbsp;µs | 17.7&nbsp;µs |
| answer_reject | standard | late_range_proof | 577 | 1000 | 0.39 | 0.41 |

## First use and memory

| rules | profile init median (ms) | p95 | peak RSS, one prove+verify (MiB) |
|---|---|---|---|
| standard | 12.8 | 15.1 | 6.0 |
| no-touch | 46.8 | 47.7 | 15.7 |

## Complete games, in-process (per player; medians over games)

| rules | shooter | games | winner's shots | bytes sent | max bytes sent | payload sent | CPU (ms) | of which setup (ms) |
|---|---|---|---|---|---|---|---|---|
| standard | hunt-target | 30 | 53 | 43012 | 49012 | 27746 | 120 | 95.6 |
| standard | random | 30 | 93 | 56154 | 58411 | 29637 | 123 | 91.7 |
| standard | sweep | 30 | 86 | 53600 | 58219 | 29176 | 128 | 98.5 |
| no-touch | hunt-target | 30 | 57 | 45666 | 49607 | 29044 | 426 | 401 |
| no-touch | random | 30 | 92 | 57018 | 59482 | 30662 | 431 | 400 |
| no-touch | sweep | 30 | 90 | 55834 | 59657 | 30259 | 427 | 397 |

### Per-message cost inside games (standard rules, all strategies)

| message | count | produce median | produce p95 | receive+verify median |
|---|---|---|---|---|
| answer_hit | 2047 | 1.54 | 1.69 | 0.44 |
| answer_miss | 11033 | 40.8&nbsp;µs | 45.6&nbsp;µs | 44.3&nbsp;µs |
| answer_sunk | 770 | 42.7&nbsp;µs | 48.7&nbsp;µs | 0.11 |
| coin_commit | 90 | 14.1&nbsp;µs | 16.1&nbsp;µs | 29.0&nbsp;µs |
| coin_nonce | 90 | 11.0&nbsp;µs | 12.3&nbsp;µs | 35.8&nbsp;µs |
| coin_reveal | 90 | 11.8&nbsp;µs | 13.3&nbsp;µs | 34.8&nbsp;µs |
| commit | 180 | 79.9 | 85.1 | 15.5 |
| shot | 13850 | 11.6&nbsp;µs | 12.8&nbsp;µs | (with answer) |

`produce` for an answer is the defender's whole handling of the incoming shot (frame check, answer, signing); `receive+verify` is the shooter's frame and answer check.

## Networked games (TCP via delay proxy, hunt-target shooters)

| RTT (ms) | link (Mbit/s) | games | setup to first shot (ms) | whole game (ms) | shot→verified median | p95 |
|---|---|---|---|---|---|---|
| 0 | unlimited | 5 | 186 | 236 | 0.31 | 2.36 |
| 50 | unlimited | 5 | 395 | 2865 | 50.8 | 56.5 |
| 150 | unlimited | 5 | 556 | 7850 | 151 | 160 |
| 50 | 10 | 5 | 355 | 2934 | 51.6 | 61.2 |

Setup covers both commits (proving and verifying) and the coin flip. The proxy adds the stated delay one way per direction; bandwidth-limited runs serialize each chunk.

