//! Standard-v1 public parameters (paper §4.1). Peers never exchange generators
//! or geometry, only `params_id`.

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::traits::Identity;
use sha2::{Digest, Sha512, Sha512_256};
use std::fmt;
use std::ops::Range;
use std::sync::OnceLock;

pub const BOARD_N: usize = 10;
pub const N: usize = BOARD_N * BOARD_N;
pub const K: usize = 5;
pub const FLEET_LENGTHS: [u8; K] = [5, 4, 3, 3, 2];
pub const T: usize = 17;
pub const P: usize = 760;
/// Sunk-report wire order.
pub const DISTINCT_LENGTHS: [u8; 4] = [5, 4, 3, 2];
pub const TOTAL_INCIDENCES: usize = 2480;

const H_DERIVATION_DOMAIN: &[u8] = b"zkbattleship/reference/v1/pedersen-H";
const PARAMS_ID_DOMAIN: &[u8] = b"zkbattleship/reference/v1/params-id";

const PROTOCOL_ID: &[u8] = b"zkbattleship";
const PROTOCOL_VERSION: u16 = 1;
const CRYPTO_SUITE_ID: &[u8] = b"ristretto255+sha512";
const ENUMERATION_RULE_ID: &[u8] = b"zkbattleship/enumeration/h-then-v";
const ENUMERATION_RULE_VERSION: u16 = 1;

/// Index `row * BOARD_N + col`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CellIndex(u8);

impl CellIndex {
    pub fn from_row_col(row: u8, col: u8) -> Option<CellIndex> {
        if row < BOARD_N as u8 && col < BOARD_N as u8 {
            Some(CellIndex(row * BOARD_N as u8 + col))
        } else {
            None
        }
    }

    pub fn from_index(index: u8) -> Option<CellIndex> {
        if (index as usize) < N {
            Some(CellIndex(index))
        } else {
            None
        }
    }

    pub fn index(self) -> u8 {
        self.0
    }

    pub fn row(self) -> u8 {
        self.0 / BOARD_N as u8
    }

    pub fn col(self) -> u8 {
        self.0 % BOARD_N as u8
    }
}

/// Violated legality condition (L1)-(L3) of paper Lemma 3.2.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PlacementError {
    WrongLength {
        expected: usize,
        actual: usize,
    },
    /// (L1)
    NonBitEntry {
        position: usize,
        value: u8,
    },
    /// (L2)
    BlockNotOneHot {
        block: usize,
        sum: u64,
    },
    /// (L3)
    OverlappingShips {
        cell: u8,
    },
}

impl fmt::Display for PlacementError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PlacementError::WrongLength { expected, actual } => {
                write!(
                    f,
                    "placement vector has length {actual}, expected {expected}"
                )
            }
            PlacementError::NonBitEntry { position, value } => {
                write!(f, "placement entry {position} is not a bit (value {value})")
            }
            PlacementError::BlockNotOneHot { block, sum } => {
                write!(
                    f,
                    "block {block} selects {sum} positions, expected exactly 1"
                )
            }
            PlacementError::OverlappingShips { cell } => {
                write!(
                    f,
                    "cell {cell} is covered by more than one selected position"
                )
            }
        }
    }
}

impl std::error::Error for PlacementError {}

/// Enumeration rule: per block, all horizontal positions (`row = 0..n`, then
/// `col = 0..=n-len`), then all vertical (`col = 0..n`, then `row = 0..=n-len`);
/// global index `p` = block offset + in-block index.
pub struct Geometry {
    block_starts: [usize; K],
    block_sizes: [usize; K],
    cells_of_position: Vec<Box<[CellIndex]>>,
    block_of_position: Vec<u8>,
    support_of_cell: Vec<Box<[usize]>>,
}

impl Geometry {
    fn standard() -> Geometry {
        let mut cells_of_position: Vec<Box<[CellIndex]>> = Vec::with_capacity(P);
        let mut block_of_position: Vec<u8> = Vec::with_capacity(P);
        let mut block_starts = [0usize; K];
        let mut block_sizes = [0usize; K];
        let mut support_of_cell: Vec<Vec<usize>> = vec![Vec::new(); N];

        for (block, &len) in FLEET_LENGTHS.iter().enumerate() {
            let len = len as usize;
            block_starts[block] = cells_of_position.len();

            let mut push_position = |cells: Vec<CellIndex>| {
                let p = cells_of_position.len();
                for &cell in &cells {
                    support_of_cell[cell.index() as usize].push(p);
                }
                cells_of_position.push(cells.into_boxed_slice());
                block_of_position.push(block as u8);
            };

            for row in 0..BOARD_N {
                for col in 0..=(BOARD_N - len) {
                    let cells = (0..len)
                        .map(|j| CellIndex::from_row_col(row as u8, (col + j) as u8).unwrap())
                        .collect();
                    push_position(cells);
                }
            }
            for col in 0..BOARD_N {
                for row in 0..=(BOARD_N - len) {
                    let cells = (0..len)
                        .map(|j| CellIndex::from_row_col((row + j) as u8, col as u8).unwrap())
                        .collect();
                    push_position(cells);
                }
            }

            block_sizes[block] = cells_of_position.len() - block_starts[block];
        }

        let incidences: usize = cells_of_position.iter().map(|c| c.len()).sum();
        assert_eq!(block_sizes, [120, 140, 160, 160, 180]);
        assert_eq!(cells_of_position.len(), P);
        assert_eq!(incidences, TOTAL_INCIDENCES);
        debug_assert!(cells_of_position
            .iter()
            .all(|cells| cells.windows(2).all(|w| w[0] < w[1])));
        debug_assert!(support_of_cell
            .iter()
            .all(|support| support.windows(2).all(|w| w[0] < w[1])));

        Geometry {
            block_starts,
            block_sizes,
            cells_of_position,
            block_of_position,
            support_of_cell: support_of_cell
                .into_iter()
                .map(Vec::into_boxed_slice)
                .collect(),
        }
    }

    pub fn board_n(&self) -> usize {
        BOARD_N
    }

    pub fn n_cells(&self) -> usize {
        N
    }

    pub fn k(&self) -> usize {
        K
    }

    pub fn t(&self) -> usize {
        T
    }

    pub fn p(&self) -> usize {
        self.cells_of_position.len()
    }

    pub fn fleet_lengths(&self) -> &[u8; K] {
        &FLEET_LENGTHS
    }

    pub fn distinct_lengths(&self) -> &[u8; 4] {
        &DISTINCT_LENGTHS
    }

    pub fn block_range(&self, block: usize) -> Range<usize> {
        self.block_starts[block]..self.block_starts[block] + self.block_sizes[block]
    }

    pub fn block_size(&self, block: usize) -> usize {
        self.block_sizes[block]
    }

    pub fn cells_of_position(&self, p: usize) -> &[CellIndex] {
        &self.cells_of_position[p]
    }

    pub fn block_of_position(&self, p: usize) -> usize {
        self.block_of_position[p] as usize
    }

    pub fn ship_length_of_block(&self, block: usize) -> u8 {
        FLEET_LENGTHS[block]
    }

    pub fn ship_count_of_length(&self, length: u8) -> u8 {
        FLEET_LENGTHS.iter().filter(|&&l| l == length).count() as u8
    }

    /// Row `M_i` of the incidence matrix, as sorted position indices.
    pub fn support_of_cell(&self, cell: CellIndex) -> &[usize] {
        &self.support_of_cell[cell.index() as usize]
    }

    /// Paper Lemma 3.2 (L1)-(L3).
    pub fn validate_placement(&self, e: &[u8]) -> Result<(), PlacementError> {
        if e.len() != self.p() {
            return Err(PlacementError::WrongLength {
                expected: self.p(),
                actual: e.len(),
            });
        }
        // (L1)
        for (p, &v) in e.iter().enumerate() {
            if v > 1 {
                return Err(PlacementError::NonBitEntry {
                    position: p,
                    value: v,
                });
            }
        }
        // (L2)
        for block in 0..K {
            let sum: u64 = e[self.block_range(block)]
                .iter()
                .map(|&v| u64::from(v))
                .sum();
            if sum != 1 {
                return Err(PlacementError::BlockNotOneHot { block, sum });
            }
        }
        // (L3) over every cell's public support: traversal selected by a
        // secret e[p] would leak the placement through branches/memory access.
        for i in 0..N {
            let cell = CellIndex::from_index(i as u8).expect("i < N");
            let cover: u64 = self
                .support_of_cell(cell)
                .iter()
                .map(|&p| u64::from(e[p]))
                .sum();
            if cover > 1 {
                return Err(PlacementError::OverlappingShips { cell: i as u8 });
            }
        }
        Ok(())
    }

    pub fn is_legal_placement(&self, e: &[u8]) -> bool {
        self.validate_placement(e).is_ok()
    }
}

pub struct Parameters {
    geometry: Geometry,
    g: RistrettoPoint,
    h: RistrettoPoint,
    g_bytes: [u8; 32],
    h_bytes: [u8; 32],
    canonical_bytes: Box<[u8]>,
    params_id: [u8; 32],
}

impl Parameters {
    /// `G` = Ristretto basepoint; `H` = hash-to-group of the domain string,
    /// never `scalar * G` (that would publish `log_G H` and break binding).
    pub fn standard_v1() -> &'static Parameters {
        static STANDARD: OnceLock<Parameters> = OnceLock::new();
        STANDARD.get_or_init(|| {
            let g = RISTRETTO_BASEPOINT_POINT;
            let h = RistrettoPoint::hash_from_bytes::<Sha512>(H_DERIVATION_DOMAIN);
            assert!(
                h != RistrettoPoint::identity(),
                "derived H must not be the identity"
            );
            assert!(h != g, "derived H must differ from G");
            Parameters::new(g, h)
        })
    }

    fn new(g: RistrettoPoint, h: RistrettoPoint) -> Parameters {
        let g_bytes = g.compress().to_bytes();
        let h_bytes = h.compress().to_bytes();
        let canonical_bytes = canonical_parameter_bytes(&g_bytes, &h_bytes).into_boxed_slice();
        let params_id = derive_params_id(&canonical_bytes);
        Parameters {
            geometry: Geometry::standard(),
            g,
            h,
            g_bytes,
            h_bytes,
            canonical_bytes,
            params_id,
        }
    }

    /// Trapdoored generators for the coupling test (paper Lemma 2.3). Unreachable
    /// from production/network code; the trapdoor scalar is never stored here.
    #[cfg(test)]
    pub(crate) fn from_test_generators(g: RistrettoPoint, h: RistrettoPoint) -> Parameters {
        Parameters::new(g, h)
    }

    pub fn geometry(&self) -> &Geometry {
        &self.geometry
    }

    /// Paper `g`.
    pub fn g(&self) -> &RistrettoPoint {
        &self.g
    }

    /// Paper `h`.
    pub fn h(&self) -> &RistrettoPoint {
        &self.h
    }

    pub fn g_encoding(&self) -> &[u8; 32] {
        &self.g_bytes
    }

    pub fn h_encoding(&self) -> &[u8; 32] {
        &self.h_bytes
    }

    /// Bound in full into the Fiat-Shamir transcript (paper `pp`). Integers
    /// little-endian; strings `u16`-length-prefixed.
    ///
    /// ```text
    /// offset  size  field
    /// 0       2     u16  length of protocol identifier (= 12)
    /// 2       12    bytes  protocol identifier = "zkbattleship"
    /// 14      2     u16  protocol version (= 1)
    /// 16      2     u16  length of crypto-suite identifier (= 19)
    /// 18      19    bytes  crypto-suite identifier = "ristretto255+sha512"
    /// 37      1     u8   board size n (= 10)
    /// 38      2     u16  number of fleet blocks (= 5)
    /// 40      5     u8 × 5  ordered fleet lengths (= 05 04 03 03 02)
    /// 45      2     u16  length of enumeration-rule identifier (= 33)
    /// 47      33    bytes  enumeration-rule identifier
    ///                  = "zkbattleship/enumeration/h-then-v"
    /// 80      2     u16  enumeration-rule version (= 1)
    /// 82      32    bytes  canonical G encoding
    /// 114     32    bytes  canonical H encoding
    /// ```
    pub fn canonical_params_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    /// `SHA-512/256(PARAMS_ID_DOMAIN || canonical_params_bytes)`.
    pub fn params_id(&self) -> &[u8; 32] {
        &self.params_id
    }
}

fn push_len_prefixed(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u16).to_le_bytes());
    out.extend_from_slice(bytes);
}

fn canonical_parameter_bytes(g_bytes: &[u8; 32], h_bytes: &[u8; 32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(146);
    push_len_prefixed(&mut out, PROTOCOL_ID);
    out.extend_from_slice(&PROTOCOL_VERSION.to_le_bytes());
    push_len_prefixed(&mut out, CRYPTO_SUITE_ID);
    out.push(BOARD_N as u8);
    out.extend_from_slice(&(FLEET_LENGTHS.len() as u16).to_le_bytes());
    out.extend_from_slice(&FLEET_LENGTHS);
    push_len_prefixed(&mut out, ENUMERATION_RULE_ID);
    out.extend_from_slice(&ENUMERATION_RULE_VERSION.to_le_bytes());
    out.extend_from_slice(g_bytes);
    out.extend_from_slice(h_bytes);
    out
}

fn derive_params_id(canonical_bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha512_256::new();
    hasher.update(PARAMS_ID_DOMAIN);
    hasher.update(canonical_bytes);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn cells(geometry: &Geometry, p: usize) -> Vec<u8> {
        geometry
            .cells_of_position(p)
            .iter()
            .map(|c| c.index())
            .collect()
    }

    #[test]
    fn standard_v1_is_a_singleton() {
        assert!(std::ptr::eq(
            Parameters::standard_v1(),
            Parameters::standard_v1()
        ));
    }

    #[test]
    fn geometry_totals() {
        let geometry = Parameters::standard_v1().geometry();
        assert_eq!(
            (0..K).map(|k| geometry.block_size(k)).collect::<Vec<_>>(),
            vec![120, 140, 160, 160, 180]
        );
        assert_eq!(geometry.p(), P);
        let incidences: usize = (0..P).map(|p| geometry.cells_of_position(p).len()).sum();
        assert_eq!(incidences, TOTAL_INCIDENCES);
        assert_eq!(geometry.fleet_lengths(), &[5, 4, 3, 3, 2]);
        assert_eq!(geometry.distinct_lengths(), &[5, 4, 3, 2]);
        assert_eq!(geometry.t(), T);
    }

    #[test]
    fn block_ranges_are_contiguous() {
        let geometry = Parameters::standard_v1().geometry();
        assert_eq!(geometry.block_range(0), 0..120);
        assert_eq!(geometry.block_range(1), 120..260);
        assert_eq!(geometry.block_range(2), 260..420);
        assert_eq!(geometry.block_range(3), 420..580);
        assert_eq!(geometry.block_range(4), 580..760);
        for p in 0..P {
            assert!(geometry
                .block_range(geometry.block_of_position(p))
                .contains(&p));
        }
    }

    #[test]
    fn enumeration_order_pins() {
        let geometry = Parameters::standard_v1().geometry();

        assert_eq!(cells(geometry, 0), [0, 1, 2, 3, 4]);
        assert_eq!(cells(geometry, 1), [1, 2, 3, 4, 5]);
        assert_eq!(cells(geometry, 2), [2, 3, 4, 5, 6]);
        assert_eq!(cells(geometry, 59), [95, 96, 97, 98, 99]); // last horizontal
        assert_eq!(cells(geometry, 60), [0, 10, 20, 30, 40]); // first vertical
        assert_eq!(cells(geometry, 61), [10, 20, 30, 40, 50]);
        assert_eq!(cells(geometry, 118), [49, 59, 69, 79, 89]);
        assert_eq!(cells(geometry, 119), [59, 69, 79, 89, 99]);

        assert_eq!(cells(geometry, 120), [0, 1, 2, 3]);
        assert_eq!(cells(geometry, 121), [1, 2, 3, 4]);
        assert_eq!(cells(geometry, 122), [2, 3, 4, 5]);
        assert_eq!(cells(geometry, 189), [96, 97, 98, 99]); // last horizontal
        assert_eq!(cells(geometry, 190), [0, 10, 20, 30]); // first vertical
        assert_eq!(cells(geometry, 191), [10, 20, 30, 40]);
        assert_eq!(cells(geometry, 258), [59, 69, 79, 89]);
        assert_eq!(cells(geometry, 259), [69, 79, 89, 99]);

        assert_eq!(cells(geometry, 260), [0, 1, 2]);
        assert_eq!(cells(geometry, 261), [1, 2, 3]);
        assert_eq!(cells(geometry, 262), [2, 3, 4]);
        assert_eq!(cells(geometry, 339), [97, 98, 99]); // last horizontal
        assert_eq!(cells(geometry, 340), [0, 10, 20]); // first vertical
        assert_eq!(cells(geometry, 341), [10, 20, 30]);
        assert_eq!(cells(geometry, 418), [69, 79, 89]);
        assert_eq!(cells(geometry, 419), [79, 89, 99]);

        assert_eq!(cells(geometry, 420), [0, 1, 2]);
        assert_eq!(cells(geometry, 421), [1, 2, 3]);
        assert_eq!(cells(geometry, 499), [97, 98, 99]); // last horizontal
        assert_eq!(cells(geometry, 500), [0, 10, 20]); // first vertical
        assert_eq!(cells(geometry, 501), [10, 20, 30]);
        assert_eq!(cells(geometry, 578), [69, 79, 89]);
        assert_eq!(cells(geometry, 579), [79, 89, 99]);

        assert_eq!(cells(geometry, 580), [0, 1]);
        assert_eq!(cells(geometry, 581), [1, 2]);
        assert_eq!(cells(geometry, 669), [98, 99]); // last horizontal
        assert_eq!(cells(geometry, 670), [0, 10]); // first vertical
        assert_eq!(cells(geometry, 671), [10, 20]);
        assert_eq!(cells(geometry, 758), [79, 89]);
        assert_eq!(cells(geometry, 759), [89, 99]);
    }

    #[test]
    fn support_of_cell_pins() {
        let geometry = Parameters::standard_v1().geometry();
        let support = |index: u8| geometry.support_of_cell(CellIndex::from_index(index).unwrap());

        assert_eq!(support(0), [0, 60, 120, 190, 260, 340, 420, 500, 580, 670]);
        assert_eq!(support(9), [5, 114, 126, 253, 267, 412, 427, 572, 588, 751]);
        assert_eq!(
            support(90),
            [54, 65, 183, 196, 332, 347, 492, 507, 661, 678]
        );
        assert_eq!(
            support(99),
            [59, 119, 189, 259, 339, 419, 499, 579, 669, 759]
        );

        assert_eq!(
            support(4),
            [
                0, 1, 2, 3, 4, 84, 121, 122, 123, 124, 218, 262, 263, 264, 372, 422, 423, 424, 532,
                583, 584, 706
            ]
        );
        assert_eq!(
            support(40),
            [
                24, 60, 61, 62, 63, 64, 148, 191, 192, 193, 194, 292, 342, 343, 344, 452, 502, 503,
                504, 616, 673, 674
            ]
        );
        assert_eq!(
            support(49),
            [
                29, 114, 115, 116, 117, 118, 154, 254, 255, 256, 257, 299, 414, 415, 416, 459, 574,
                575, 576, 624, 754, 755
            ]
        );
        assert_eq!(
            support(94),
            [
                54, 55, 56, 57, 58, 89, 184, 185, 186, 187, 224, 334, 335, 336, 379, 494, 495, 496,
                539, 664, 665, 714
            ]
        );

        assert_eq!(
            support(44),
            [
                24, 25, 26, 27, 28, 84, 85, 86, 87, 88, 149, 150, 151, 152, 219, 220, 221, 222,
                294, 295, 296, 374, 375, 376, 454, 455, 456, 534, 535, 536, 619, 620, 709, 710
            ]
        );
        assert_eq!(
            support(55),
            [
                31, 32, 33, 34, 35, 91, 92, 93, 94, 95, 157, 158, 159, 160, 227, 228, 229, 230,
                303, 304, 305, 383, 384, 385, 463, 464, 465, 543, 544, 545, 629, 630, 719, 720
            ]
        );

        for index in 0..N as u8 {
            let cell = CellIndex::from_index(index).unwrap();
            for &p in geometry.support_of_cell(cell) {
                assert!(geometry.cells_of_position(p).contains(&cell));
            }
        }
    }

    #[test]
    fn generator_encodings_are_pinned() {
        let params = Parameters::standard_v1();
        assert_eq!(
            hex(params.g_encoding()),
            "e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76"
        );
        assert_eq!(
            hex(params.h_encoding()),
            "8e0798914faacfe5a3cecddc2b04bd0ee008695f09c43b2bac3342734fd54773"
        );
        assert_ne!(params.h(), &RistrettoPoint::identity());
        assert_ne!(params.h(), params.g());
    }

    #[test]
    fn params_id_is_pinned() {
        let params = Parameters::standard_v1();
        assert_eq!(params.canonical_params_bytes().len(), 146);
        assert_eq!(
            hex(params.params_id()),
            "4a4a8b5f9230d5ea83aebd24c4bc68e735623f1fccebc803ab519156f82f3cef"
        );
    }

    fn legal_placement() -> Vec<u8> {
        let mut e = vec![0u8; P];
        e[0] = 1; // block 0, cells 0-4
        e[134] = 1; // block 1, row 2: cells 20-23
        e[292] = 1; // block 2, row 4: cells 40-42
        e[460] = 1; // block 3, row 5: cells 50-52
        e[643] = 1; // block 4, row 7: cells 70-71
        e
    }

    #[test]
    fn legal_placement_is_accepted() {
        let geometry = Parameters::standard_v1().geometry();
        let e = legal_placement();
        assert_eq!(geometry.validate_placement(&e), Ok(()));
        assert!(geometry.is_legal_placement(&e));
    }

    #[test]
    fn placement_with_wrong_length_is_rejected() {
        let geometry = Parameters::standard_v1().geometry();
        let e = vec![0u8; P - 1];
        assert_eq!(
            geometry.validate_placement(&e),
            Err(PlacementError::WrongLength {
                expected: P,
                actual: P - 1
            })
        );
    }

    #[test]
    fn placement_with_non_bit_entry_is_rejected() {
        let geometry = Parameters::standard_v1().geometry();
        let mut e = legal_placement();
        e[7] = 2;
        assert_eq!(
            geometry.validate_placement(&e),
            Err(PlacementError::NonBitEntry {
                position: 7,
                value: 2
            })
        );
    }

    #[test]
    fn placement_with_empty_block_is_rejected() {
        let geometry = Parameters::standard_v1().geometry();
        let e = vec![0u8; P];
        assert_eq!(
            geometry.validate_placement(&e),
            Err(PlacementError::BlockNotOneHot { block: 0, sum: 0 })
        );
    }

    #[test]
    fn placement_with_two_positions_in_a_block_is_rejected() {
        let geometry = Parameters::standard_v1().geometry();
        let mut e = legal_placement();
        e[581] = 1; // second selected position in block 4
        assert_eq!(
            geometry.validate_placement(&e),
            Err(PlacementError::BlockNotOneHot { block: 4, sum: 2 })
        );
    }

    #[test]
    fn overlapping_placement_is_rejected() {
        let geometry = Parameters::standard_v1().geometry();
        let mut e = legal_placement();
        e[460] = 0;
        e[420] = 1; // block 3 at cells 0-2, overlapping block 0
        assert_eq!(
            geometry.validate_placement(&e),
            Err(PlacementError::OverlappingShips { cell: 0 })
        );
    }

    #[test]
    fn test_generators_do_not_touch_the_production_profile() {
        use curve25519_dalek::scalar::Scalar;

        let xi = Scalar::from(42u64);
        let h = RistrettoPoint::hash_from_bytes::<Sha512>(b"zkbattleship/test-only/H");
        let g = xi * h;
        let test_params = Parameters::from_test_generators(g, h);
        assert_eq!(test_params.g(), &g);
        assert_eq!(test_params.h(), &h);
        assert_eq!(test_params.geometry().p(), P);
        assert_ne!(
            Parameters::standard_v1().params_id(),
            test_params.params_id()
        );
    }
}
