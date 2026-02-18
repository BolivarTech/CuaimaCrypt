//! CuaimaCrypt: Symmetric hybrid cipher engine.
//!
//! Orchestrates N RakeCodecs in cascade with Walsh spread-spectrum,
//! Interleaving/DeInterleaving, CrossByte permutations, and SeedHopping.
//! Processes 128-bit blocks (two `i64` values).
//!
//! Compatible byte-for-byte with the Java CuaimaCrypt v3.1.0.

use crate::error::CuaimaCryptError;
use crate::rake_codec::RakeCodec;
use crate::random::kaos_rand::KaosRand;
use crate::random::password_sparker::PasswordSparker;
use crate::random::sparker::Sparker;
use crate::shift_codec::{ShiftCodecArena, ShiftCodecId};
use crate::walsh::WALSH_CODES;

/// Default number of RakeCodecs.
const DEFAULT_NUM_RAKES: usize = 9;

/// Number of ShiftCodecs per RakeCodec.
const SC_PER_RAKE: usize = 4;

/// Symmetric hybrid cipher engine operating on 128-bit blocks.
///
/// # Architecture
///
/// CuaimaCrypt orchestrates N RakeCodecs in cascade. Each RakeCodec contains
/// 4 ShiftCodecs in a ring topology. Between each pair of RakeCodecs, a
/// CrossByte permutation mixes the block halves. Before/after the cascade,
/// Walsh spread-spectrum and Interleaving/DeInterleaving add diffusion.
///
/// After each block, all ShiftCodec states advance (shift) and the
/// SeedHopping permutation swaps states across the entire system.
pub struct CuaimaCrypt {
    arena: ShiftCodecArena,
    rakes: Vec<RakeCodec>,
    cross_bits_sequence: Vec<i32>,
    seed_hopping_seq: Vec<i32>,
    walsh_code: usize,
    kaos_rand: Option<KaosRand>,
}

impl Default for CuaimaCrypt {
    fn default() -> Self {
        Self::new()
    }
}

impl CuaimaCrypt {
    /// Creates a new CuaimaCrypt with the default 9 RakeCodecs.
    ///
    /// # Returns
    /// A new CuaimaCrypt instance with default initial state.
    /// Call [`password`](Self::password) to initialize with a key.
    ///
    /// # Examples
    ///
    /// ```
    /// use cuaimacrypt::CuaimaCrypt;
    ///
    /// let mut cc = CuaimaCrypt::new();
    /// cc.password("secret").unwrap();
    /// ```
    pub fn new() -> Self {
        Self::build(DEFAULT_NUM_RAKES)
    }

    /// Creates a new CuaimaCrypt with a custom number of RakeCodecs.
    ///
    /// More RakeCodecs increase security at the cost of throughput.
    ///
    /// # Parameters
    /// - `num_rakes`: Number of RakeCodecs (minimum 2, maximum 1024).
    ///
    /// # Errors
    /// Returns [`CuaimaCryptError::InvalidNumRakeCodecs`] if `num_rakes < 2`
    /// or `num_rakes > 1024`.
    ///
    /// # Examples
    ///
    /// ```
    /// use cuaimacrypt::CuaimaCrypt;
    ///
    /// let mut cc = CuaimaCrypt::with_num_rakes(16).unwrap();
    /// cc.password("secret").unwrap();
    /// ```
    ///
    /// ```
    /// use cuaimacrypt::CuaimaCrypt;
    ///
    /// let result = CuaimaCrypt::with_num_rakes(1);
    /// assert!(result.is_err());
    /// ```
    pub fn with_num_rakes(num_rakes: usize) -> Result<Self, CuaimaCryptError> {
        if !(2..=1024).contains(&num_rakes) {
            return Err(CuaimaCryptError::InvalidNumRakeCodecs);
        }
        Ok(Self::build(num_rakes))
    }

    /// Internal constructor shared by `new()` and `with_num_rakes()`.
    fn build(num_rakes: usize) -> Self {
        let mut arena = ShiftCodecArena::with_capacity(num_rakes * SC_PER_RAKE);
        let mut rakes = Vec::with_capacity(num_rakes);
        for _ in 0..num_rakes {
            rakes.push(RakeCodec::new(&mut arena));
        }

        // Default CrossBitsSequence: cycling 0, 1, 2, 0, 1, 2, ...
        let num_cross = num_rakes - 1;
        let mut cross_bits_sequence = vec![0i32; num_cross];
        let mut j = 0i32;
        for item in cross_bits_sequence.iter_mut() {
            *item = j;
            j += 1;
            if j > 2 {
                j = 0;
            }
        }

        // Default SeedHoppingSeq: [1, 2, 3, ..., N-1, 0]
        let num_seeds = SC_PER_RAKE * num_rakes;
        let mut seed_hopping_seq = vec![0i32; num_seeds];
        let mut j = 1i32;
        for item in seed_hopping_seq.iter_mut() {
            *item = j;
            j += 1;
            if j >= num_seeds as i32 {
                j = 0;
            }
        }

        CuaimaCrypt {
            arena,
            rakes,
            cross_bits_sequence,
            seed_hopping_seq,
            walsh_code: 0,
            kaos_rand: None,
        }
    }

    /// Initializes the cipher from a password string (Key Derivation Function).
    ///
    /// Derives all internal state (seeds, chain topology, cross-bit sequence,
    /// seed hopping sequence, window positions, shift leaps, Walsh code) from
    /// the given password using PasswordSparker and KAOSrand.
    ///
    /// # Parameters
    /// - `passw`: The password string (minimum 1 character).
    ///
    /// # Errors
    /// Returns [`CuaimaCryptError::PasswordTooShort`] if the password is too short.
    ///
    /// # Examples
    ///
    /// ```
    /// use cuaimacrypt::CuaimaCrypt;
    ///
    /// let mut cc = CuaimaCrypt::new();
    /// assert!(cc.password("valid_password").is_ok());
    /// ```
    ///
    /// ```
    /// use cuaimacrypt::CuaimaCrypt;
    ///
    /// let mut cc = CuaimaCrypt::new();
    /// assert!(cc.password("").is_err());
    /// ```
    pub fn password(&mut self, passw: &str) -> Result<(), CuaimaCryptError> {
        let mut sparker = PasswordSparker::new(passw);
        if sparker.password_ok() != 0 {
            return Err(CuaimaCryptError::PasswordTooShort);
        }

        let mut kaos = KaosRand::from_sparker(&mut sparker as &mut dyn Sparker);
        let system_num_seed = self.num_seeds();

        // Set seeds for all ShiftCodecs
        for i in 0..system_num_seed {
            let seed = kaos.next_long();
            self.set_seed(i, seed);
        }

        // Set CrossBits types
        let num_cross = self.cross_bits_sequence.len();
        for i in 0..num_cross {
            self.cross_bits_sequence[i] = kaos.next_int_bounded(4);
        }

        // Set SeedHopping sequence via RandDistribuidor
        let num_hopping = self.seed_hopping_seq.len();
        self.seed_hopping_seq = Self::rand_distribuidor(&mut kaos, num_hopping);

        // Set UpChain permutation
        let chain_seq_up = Self::rand_distribuidor(&mut kaos, system_num_seed);
        for (j, &target_index) in chain_seq_up.iter().enumerate() {
            let target_id = self.get_shift_codec_id(target_index as usize);
            self.set_upchain(j, target_id);
        }

        // Set DownChain permutation
        let chain_seq_down = Self::rand_distribuidor(&mut kaos, system_num_seed);
        for (j, &target_index) in chain_seq_down.iter().enumerate() {
            let target_id = self.get_shift_codec_id(target_index as usize);
            self.set_downchain(j, target_id);
        }

        // Set ShiftCodec parameters (PosUp, PosDown, WinA, WinB, ShiftLeap)
        self.init_shift_codec_params(&mut kaos, system_num_seed, 32, Self::set_pos_up);
        self.init_shift_codec_params(&mut kaos, system_num_seed, 32, Self::set_pos_down);
        self.init_shift_codec_params(&mut kaos, system_num_seed, 32, Self::set_win_a);
        self.init_shift_codec_params(&mut kaos, system_num_seed, 32, Self::set_win_b);
        self.init_shift_codec_params(&mut kaos, system_num_seed, 15, Self::set_shift_leap);

        // Calculate Walsh code (1..127, never 0)
        self.walsh_code = kaos.next_int_bounded(128) as usize;
        if self.walsh_code == 0 {
            self.walsh_code = 1;
        }

        self.kaos_rand = Some(kaos);
        Ok(())
    }

    /// Encrypts a 128-bit block in place.
    ///
    /// The cipher state advances after each call, so encrypting the same
    /// plaintext twice produces different ciphertext (stream cipher property).
    ///
    /// # Parameters
    /// - `block`: The 128-bit block to encrypt (two `i64` values, modified in place).
    ///
    /// # Examples
    ///
    /// ```
    /// use cuaimacrypt::CuaimaCrypt;
    ///
    /// let mut cc = CuaimaCrypt::new();
    /// cc.password("secret").unwrap();
    ///
    /// let mut block: [i64; 2] = [42, 84];
    /// cc.codec(&mut block);
    /// assert_ne!(block, [42, 84]);
    /// ```
    pub fn codec(&mut self, block: &mut [i64; 2]) {
        let num_rca = self.rakes.len();

        // Walsh spread-spectrum XOR
        block[0] ^= WALSH_CODES[self.walsh_code][0];
        block[1] ^= WALSH_CODES[self.walsh_code][1];

        // Interleaving
        Self::interleaving(block);

        // Cascade: encode + cross_byte between each pair
        for i in 0..(num_rca - 1) {
            self.rakes[i].codec(&mut self.arena, block);
            let cross = self.cross_bits_sequence[i];
            Self::cross_byte(cross, block);
        }
        // Last RakeCodec (no CrossByte after)
        self.rakes[num_rca - 1].codec(&mut self.arena, block);

        // Advance all ShiftCodecs (encoding)
        for i in 0..num_rca {
            self.rakes[i].shift_codec(&mut self.arena);
        }

        // SeedHopping
        self.seed_hop();
    }

    /// Decrypts a 128-bit block in place.
    ///
    /// Must be called on the same sequential block position as the
    /// corresponding [`codec`](Self::codec) call on the encoder instance.
    ///
    /// # Parameters
    /// - `block`: The 128-bit block to decrypt (two `i64` values, modified in place).
    ///
    /// # Examples
    ///
    /// ```
    /// use cuaimacrypt::CuaimaCrypt;
    ///
    /// let mut encoder = CuaimaCrypt::new();
    /// encoder.password("secret").unwrap();
    /// let mut decoder = CuaimaCrypt::new();
    /// decoder.password("secret").unwrap();
    ///
    /// let original: [i64; 2] = [42, 84];
    /// let mut block = original;
    /// encoder.codec(&mut block);
    /// decoder.decodec(&mut block);
    /// assert_eq!(block, original);
    /// ```
    pub fn decodec(&mut self, block: &mut [i64; 2]) {
        let num_rca = self.rakes.len();

        // Reverse cascade: decode from last to first
        for i in (1..num_rca).rev() {
            self.rakes[i].decodec(&mut self.arena, block);
            let cross = self.cross_bits_sequence[i - 1];
            Self::cross_byte(cross, block);
        }
        self.rakes[0].decodec(&mut self.arena, block);

        // DeInterleaving
        Self::de_interleaving(block);

        // Walsh de-spread XOR
        block[0] ^= WALSH_CODES[self.walsh_code][0];
        block[1] ^= WALSH_CODES[self.walsh_code][1];

        // Advance all ShiftCodecs (decoding)
        for i in 0..num_rca {
            self.rakes[i].shift_decodec(&mut self.arena);
        }

        // SeedHopping
        self.seed_hop();
    }

    /// Resets all ShiftCodecs to their seed states.
    ///
    /// After reset, encrypting the same plaintext sequence produces the
    /// same ciphertext as after the initial [`password`](Self::password) call.
    ///
    /// # Examples
    ///
    /// ```
    /// use cuaimacrypt::CuaimaCrypt;
    ///
    /// let mut cc = CuaimaCrypt::new();
    /// cc.password("secret").unwrap();
    ///
    /// let mut b1: [i64; 2] = [1, 2];
    /// cc.codec(&mut b1);
    /// cc.reset();
    ///
    /// let mut b2: [i64; 2] = [1, 2];
    /// cc.codec(&mut b2);
    /// assert_eq!(b1, b2);
    /// ```
    pub fn reset(&mut self) {
        for rake in &self.rakes {
            rake.reset(&mut self.arena);
        }
    }

    /// Returns the total number of ShiftCodecs in the system.
    pub fn num_seeds(&self) -> usize {
        SC_PER_RAKE * self.rakes.len()
    }

    /// Returns the seed value of the ShiftCodec at flat index `ns`.
    ///
    /// # Parameters
    /// - `ns`: Flat ShiftCodec index (0..num_seeds).
    ///
    /// # Returns
    /// The seed value, or 0 if the index is out of range.
    pub fn get_seed_value(&self, ns: usize) -> i64 {
        if ns >= self.num_seeds() {
            return 0;
        }
        let id = self.get_shift_codec_id(ns);
        self.arena.get_seed(id)
    }

    // ──────── Helper: flat ShiftCodec addressing ────────

    /// Converts a flat index (0..num_seeds) to (rake_index, sc_within_rake).
    fn flat_to_rake_sc(&self, index: usize) -> (usize, usize) {
        let pos_rca = index / SC_PER_RAKE;
        let num_sc = index - (pos_rca * SC_PER_RAKE);
        (pos_rca, num_sc)
    }

    /// Returns the ShiftCodecId for a flat index.
    fn get_shift_codec_id(&self, index: usize) -> ShiftCodecId {
        let (pos_rca, num_sc) = self.flat_to_rake_sc(index);
        self.rakes[pos_rca].get_shift_codec(num_sc)
    }

    /// Sets the seed of the ShiftCodec at flat index `ns`.
    fn set_seed(&mut self, ns: usize, seed: i64) {
        let id = self.get_shift_codec_id(ns);
        self.arena.set_seed(id, seed);
    }

    /// Sets the UpChain of ShiftCodec at flat index `sc` to `target`.
    fn set_upchain(&mut self, sc: usize, target: ShiftCodecId) {
        let id = self.get_shift_codec_id(sc);
        self.arena.set_upchain(id, target);
    }

    /// Sets the DownChain of ShiftCodec at flat index `sc` to `target`.
    fn set_downchain(&mut self, sc: usize, target: ShiftCodecId) {
        let id = self.get_shift_codec_id(sc);
        self.arena.set_downchain(id, target);
    }

    /// Sets PosUp for ShiftCodec at flat index.
    fn set_pos_up(&mut self, sc: usize, pos: i32) {
        let id = self.get_shift_codec_id(sc);
        self.arena.set_pos_up(id, pos);
    }

    /// Sets PosDown for ShiftCodec at flat index.
    fn set_pos_down(&mut self, sc: usize, pos: i32) {
        let id = self.get_shift_codec_id(sc);
        self.arena.set_pos_down(id, pos);
    }

    /// Sets WinA for ShiftCodec at flat index.
    fn set_win_a(&mut self, sc: usize, pos: i32) {
        let id = self.get_shift_codec_id(sc);
        self.arena.set_win_a(id, pos);
    }

    /// Sets WinB for ShiftCodec at flat index.
    fn set_win_b(&mut self, sc: usize, pos: i32) {
        let id = self.get_shift_codec_id(sc);
        self.arena.set_win_b(id, pos);
    }

    /// Sets ShiftLeap for ShiftCodec at flat index.
    fn set_shift_leap(&mut self, sc: usize, leap: i32) {
        let id = self.get_shift_codec_id(sc);
        self.arena.set_shift_leap(id, leap);
    }

    /// Initializes a ShiftCodec parameter for all codecs using KaosRand.
    ///
    /// # Parameters
    /// - `kaos`: The KAOSrand PRNG for generating values.
    /// - `count`: Number of ShiftCodecs to initialize.
    /// - `bound`: Exclusive upper bound for `next_int_bounded`.
    /// - `setter`: The setter method to call for each ShiftCodec.
    fn init_shift_codec_params(
        &mut self,
        kaos: &mut KaosRand,
        count: usize,
        bound: i32,
        setter: fn(&mut Self, usize, i32),
    ) {
        for j in 0..count {
            let k = kaos.next_int_bounded(bound);
            setter(self, j, k);
        }
    }

    // ──────── SeedHop ────────

    /// Permutes ShiftCodec states according to the seed hopping sequence.
    ///
    /// For each position i, swaps the state of ShiftCodec[i] with
    /// ShiftCodec[SeedHoppingSeq[i]].
    fn seed_hop(&mut self) {
        let num_seed = self.seed_hopping_seq.len();
        for i in 0..num_seed {
            let hop_to = self.seed_hopping_seq[i];
            if hop_to >= 0 && (hop_to as usize) < num_seed {
                // Swap states of ShiftCodec[i] and ShiftCodec[hop_to]
                let id_i = self.get_shift_codec_id(i);
                let id_hop = self.get_shift_codec_id(hop_to as usize);
                self.arena.swap_states(id_i, id_hop);
            }
        }
    }

    // ──────── RandDistribuidor ────────

    /// Fisher-Yates-like random distribution.
    ///
    /// Creates a permutation of `[0..num_values)` where the last 2 elements
    /// are assigned in reverse order from the remaining support array.
    ///
    /// # Parameters
    /// - `kaos`: The KAOSrand PRNG.
    /// - `num_values`: The number of values to distribute.
    ///
    /// # Returns
    /// A `Vec<i32>` containing the permutation.
    fn rand_distribuidor(kaos: &mut KaosRand, num_values: usize) -> Vec<i32> {
        if num_values == 0 {
            return Vec::new();
        }

        let mut salida = vec![0i32; num_values];
        let mut soporte: Vec<i32> = (0..num_values as i32).collect();

        let mut sop_limit = num_values;
        // Process all except last 2
        for salida_item in salida.iter_mut().take(num_values - 2) {
            let k = kaos.next_int_bounded(sop_limit as i32) as usize;
            *salida_item = soporte[k];
            // Shift remaining elements left to fill the gap
            for j in k..(sop_limit - 1) {
                soporte[j] = soporte[j + 1];
            }
            sop_limit -= 1;
        }
        // Last 2 in reverse order
        salida[num_values - 2] = soporte[1];
        salida[num_values - 1] = soporte[0];

        salida
    }

    // ──────── CrossByte operations ────────

    /// Dispatches to the appropriate CrossByte operation.
    ///
    /// - 0: InnerCrossByte
    /// - 1: OutneerCrossByte
    /// - 2: InterCrossByte
    /// - 3: SwapByte
    fn cross_byte(num: i32, block: &mut [i64; 2]) {
        match num {
            0 => Self::inner_cross_byte(block),
            1 => Self::outneer_cross_byte(block),
            2 => Self::inter_cross_byte(block),
            3 => Self::swap_byte(block),
            _ => {}
        }
    }

    /// Splits an i64 into its high and low 32-bit halves.
    ///
    /// Returns `(high_32, low_32)` where each half is stored in the low 32 bits
    /// of an i64, zero-extended.
    fn split_halves(val: i64) -> (i64, i64) {
        let high = ((val as u64) >> 32) as i64;
        let low = (((val << 32) as u64) >> 32) as i64;
        (high, low)
    }

    /// Joins high and low 32-bit halves into an i64.
    ///
    /// Each half is expected in the low 32 bits of its i64 argument.
    fn join_halves(high: i64, low: i64) -> i64 {
        (high << 32) | (((low << 32) as u64 >> 32) as i64)
    }

    /// Crosses the inner 32-bit halves between block[0] and block[1].
    ///
    /// block[0] = high32(A) : high32(B)
    /// block[1] = low32(A) : low32(B)
    fn inner_cross_byte(block: &mut [i64; 2]) {
        let (a_hi, a_lo) = Self::split_halves(block[0]);
        let (b_hi, b_lo) = Self::split_halves(block[1]);
        block[0] = Self::join_halves(a_hi, b_hi);
        block[1] = Self::join_halves(a_lo, b_lo);
    }

    /// Crosses the outer 32-bit halves between block[0] and block[1].
    ///
    /// block[0] = low32(B) : low32(A)
    /// block[1] = high32(B) : high32(A)
    fn outneer_cross_byte(block: &mut [i64; 2]) {
        let (a_hi, a_lo) = Self::split_halves(block[0]);
        let (b_hi, b_lo) = Self::split_halves(block[1]);
        block[0] = Self::join_halves(b_lo, a_lo);
        block[1] = Self::join_halves(b_hi, a_hi);
    }

    /// Swaps high and low 32-bit halves within each word.
    ///
    /// block[0] = low32(A) : high32(A)
    /// block[1] = low32(B) : high32(B)
    fn inter_cross_byte(block: &mut [i64; 2]) {
        let (a_hi, a_lo) = Self::split_halves(block[0]);
        let (b_hi, b_lo) = Self::split_halves(block[1]);
        block[0] = Self::join_halves(a_lo, a_hi);
        block[1] = Self::join_halves(b_lo, b_hi);
    }

    /// Swaps 32-bit halves within each word and then swaps the two words.
    ///
    /// block[0] = low32(B) : high32(B)
    /// block[1] = low32(A) : high32(A)
    fn swap_byte(block: &mut [i64; 2]) {
        let (a_hi, a_lo) = Self::split_halves(block[0]);
        let (b_hi, b_lo) = Self::split_halves(block[1]);
        block[0] = Self::join_halves(b_lo, b_hi);
        block[1] = Self::join_halves(a_lo, a_hi);
    }

    // ──────── Bit manipulation helpers ────────

    /// Returns a single bit from `input` at position `pos` (0..63).
    ///
    /// Bit 0 is the LSB.
    fn get_bit(input: i64, pos: i32) -> i64 {
        let shift = 63 - pos;
        let sr = input << shift;
        ((sr as u64) >> 63) as i64
    }

    /// Returns 8 bits from `input` starting at position `pos` (0..56).
    ///
    /// Position 0 returns the most significant byte.
    fn get_8_bits(input: i64, pos: i32) -> i64 {
        let shift = 56 - pos;
        let sr = input << shift;
        ((sr as u64) >> 56) as i64
    }

    /// Transposes a 64-bit value treated as an 8x8 bit matrix (left transpose).
    ///
    /// Iterates bit-by-bit: for each bit position (0..7), extracts bits from
    /// groups 7 down to 0, building the transposed value.
    fn transpose_left(input: i64) -> i64 {
        let mut sr: i64 = 0;
        for bit in 0..8 {
            for grupo in (0..8).rev() {
                sr <<= 1;
                let temp = Self::get_bit(input, 8 * grupo + bit);
                sr |= temp;
            }
        }
        sr
    }

    /// Transposes a 64-bit value treated as an 8x8 bit matrix (right transpose).
    ///
    /// Iterates bit-by-bit: for each bit position (7 down to 0), extracts bits
    /// from groups 0 to 7, building the transposed value.
    fn transpose_right(input: i64) -> i64 {
        let mut sr: i64 = 0;
        for bit in (0..8).rev() {
            for grupo in 0..8 {
                sr <<= 1;
                let temp = Self::get_bit(input, 8 * grupo + bit);
                sr |= temp;
            }
        }
        sr
    }

    // ──────── Interleaving / DeInterleaving ────────

    /// Performs interleaving on a 128-bit block.
    ///
    /// Mixes the 8-bit rows of both words using a two-stage process with
    /// matrix bit transposition between stages.
    fn interleaving(block: &mut [i64; 2]) {
        let mut temporal = [0i64; 2];

        // Stage 1: Cross first rows of A with last rows of B
        for i in 0..4 {
            temporal[0] <<= 8;
            temporal[0] |= Self::get_8_bits(block[0], 8 * i);
            temporal[0] <<= 8;
            temporal[0] |= Self::get_8_bits(block[1], 8 * (7 - i));
        }
        // Cross last rows of A with first rows of B
        for i in 0..4 {
            temporal[1] <<= 8;
            temporal[1] |= Self::get_8_bits(block[0], 8 * (7 - i));
            temporal[1] <<= 8;
            temporal[1] |= Self::get_8_bits(block[1], 8 * i);
        }

        // Transpose bits
        block[0] = Self::transpose_right(temporal[0]);
        block[1] = Self::transpose_left(temporal[1]);
        temporal[0] = block[0];
        temporal[1] = block[1];

        // Stage 2: Cross rows of A with rows of B (first 4)
        for i in 0..4 {
            temporal[0] <<= 8;
            temporal[0] |= Self::get_8_bits(block[0], 8 * i);
            temporal[0] <<= 8;
            temporal[0] |= Self::get_8_bits(block[1], 8 * i);
        }
        // Cross rows of A with rows of B (last 4)
        for i in 4..8 {
            temporal[1] <<= 8;
            temporal[1] |= Self::get_8_bits(block[0], 8 * i);
            temporal[1] <<= 8;
            temporal[1] |= Self::get_8_bits(block[1], 8 * i);
        }

        // Transpose bits
        block[0] = Self::transpose_right(temporal[0]);
        block[1] = Self::transpose_left(temporal[1]);
    }

    /// Performs de-interleaving on a 128-bit block (inverse of interleaving).
    fn de_interleaving(block: &mut [i64; 2]) {
        let mut temporal = [0i64; 2];

        // Stage 1: Reverse transpose
        temporal[0] = Self::transpose_left(block[0]);
        temporal[1] = Self::transpose_right(block[1]);
        block[0] = temporal[0];
        block[1] = temporal[1];
        temporal[0] = 0;
        temporal[1] = 0;

        // Reverse cross rows (first loop)
        let mut i = 0;
        while i < 8 {
            temporal[0] <<= 8;
            temporal[0] |= Self::get_8_bits(block[1], 8 * (i + 1));
            temporal[1] <<= 8;
            temporal[1] |= Self::get_8_bits(block[1], 8 * i);
            i += 2;
        }
        // Reverse cross rows (second loop)
        let mut i = 0;
        while i < 8 {
            temporal[0] <<= 8;
            temporal[0] |= Self::get_8_bits(block[0], 8 * (i + 1));
            temporal[1] <<= 8;
            temporal[1] |= Self::get_8_bits(block[0], 8 * i);
            i += 2;
        }

        // Stage 2: Reverse transpose
        block[0] = Self::transpose_left(temporal[0]);
        block[1] = Self::transpose_right(temporal[1]);
        temporal[0] = 0;
        temporal[1] = 0;

        // Reverse first/last row crossing (first loop)
        let mut i = 7;
        while i >= 1 {
            temporal[0] <<= 8;
            temporal[0] |= Self::get_8_bits(block[1], 8 * i);
            temporal[1] <<= 8;
            temporal[1] |= Self::get_8_bits(block[0], 8 * (i - 1));
            i -= 2;
        }
        // Reverse first/last row crossing (second loop)
        let mut i = 0;
        while i < 8 {
            temporal[0] <<= 8;
            temporal[0] |= Self::get_8_bits(block[0], 8 * (i + 1));
            temporal[1] <<= 8;
            temporal[1] |= Self::get_8_bits(block[1], 8 * i);
            i += 2;
        }

        block[0] = temporal[0];
        block[1] = temporal[1];
    }
}

impl Drop for CuaimaCrypt {
    /// Securely clears sensitive internal state on drop.
    fn drop(&mut self) {
        self.seed_hopping_seq.fill(0);
        self.cross_bits_sequence.fill(0);
        self.walsh_code = 0;
        // ShiftCodecArena::drop handles codec zeroing
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Known-bad passwords that produce `get_short_spark() % 25 == 0`,
    /// triggering BUG-001.
    const BAD_PASSWORDS: [&str; 3] = ["SizeSweep_4", "Pow2Sweep_512", "Pow2Sweep_2048"];

    /// Plaintext vectors used across multiple BUG-001 regression tests.
    const PLAINTEXTS: [[i64; 2]; 5] = [
        [0x0102030405060708, 0x090A0B0C0D0E0F10],
        [0, 0],
        [-1, -1],
        [i64::MAX, i64::MIN],
        [42, 84],
    ];

    #[test]
    fn test_default_construction() {
        let cc = CuaimaCrypt::new();
        assert_eq!(cc.rakes.len(), 9);
        assert_eq!(cc.num_seeds(), 36);
        assert_eq!(cc.cross_bits_sequence.len(), 8);
        assert_eq!(cc.walsh_code, 0);
    }

    #[test]
    fn test_custom_num_rakes() {
        let cc = CuaimaCrypt::with_num_rakes(4).unwrap();
        assert_eq!(cc.rakes.len(), 4);
        assert_eq!(cc.num_seeds(), 16);
        assert_eq!(cc.cross_bits_sequence.len(), 3);
    }

    #[test]
    fn test_invalid_num_rakes() {
        assert!(matches!(
            CuaimaCrypt::with_num_rakes(1),
            Err(CuaimaCryptError::InvalidNumRakeCodecs)
        ));
        assert!(matches!(
            CuaimaCrypt::with_num_rakes(1025),
            Err(CuaimaCryptError::InvalidNumRakeCodecs)
        ));
    }

    #[test]
    fn test_password_initializes_state() {
        let mut cc = CuaimaCrypt::new();
        cc.password("TestPassword123").unwrap();
        assert_ne!(cc.walsh_code, 0);
        assert!(cc.kaos_rand.is_some());
    }

    #[test]
    fn test_password_too_short() {
        let mut cc = CuaimaCrypt::new();
        let result = cc.password("");
        assert_eq!(result, Err(CuaimaCryptError::PasswordTooShort));
    }

    #[test]
    fn test_codec_decodec_roundtrip() {
        let mut encoder = CuaimaCrypt::new();
        encoder.password("TestRoundTrip2024").unwrap();

        let mut decoder = CuaimaCrypt::new();
        decoder.password("TestRoundTrip2024").unwrap();

        let original: [i64; 2] = [0x0123456789ABCDEF_u64 as i64, 0xFEDCBA9876543210_u64 as i64];
        let mut block = original;

        encoder.codec(&mut block);
        assert_ne!(
            block, original,
            "Encrypted block should differ from original"
        );

        decoder.decodec(&mut block);
        assert_eq!(block, original, "Decrypted block should match original");
    }

    #[test]
    fn test_multi_block_roundtrip() {
        let mut encoder = CuaimaCrypt::new();
        encoder.password("MultiBlock2024").unwrap();

        let mut decoder = CuaimaCrypt::new();
        decoder.password("MultiBlock2024").unwrap();

        let blocks: Vec<[i64; 2]> = vec![
            [1, 2],
            [0x0123456789ABCDEF_u64 as i64, 0xFEDCBA9876543210_u64 as i64],
            [i64::MAX, i64::MIN],
            [0, 0],
            [-1, -1],
        ];

        let mut encrypted = blocks.clone();
        for block in encrypted.iter_mut() {
            encoder.codec(block);
        }

        // Verify encryption changed values
        for (enc, orig) in encrypted.iter().zip(blocks.iter()) {
            assert_ne!(enc, orig);
        }

        // Decrypt and verify
        for (i, block) in encrypted.iter_mut().enumerate() {
            decoder.decodec(block);
            assert_eq!(*block, blocks[i], "Block {} mismatch after decrypt", i);
        }
    }

    #[test]
    fn test_same_plaintext_different_ciphertext() {
        let mut cc = CuaimaCrypt::new();
        cc.password("StreamCipher2024").unwrap();

        let mut block1 = [42i64, 84];
        let mut block2 = [42i64, 84];

        cc.codec(&mut block1);
        cc.codec(&mut block2);

        assert_ne!(
            block1, block2,
            "Same plaintext should produce different ciphertext after state advance"
        );
    }

    #[test]
    fn test_deterministic_encryption() {
        let mut cc1 = CuaimaCrypt::new();
        cc1.password("Deterministic2024").unwrap();

        let mut cc2 = CuaimaCrypt::new();
        cc2.password("Deterministic2024").unwrap();

        let mut block1 = [0x1111111111111111_u64 as i64, 0x2222222222222222_u64 as i64];
        let mut block2 = [0x1111111111111111_u64 as i64, 0x2222222222222222_u64 as i64];

        cc1.codec(&mut block1);
        cc2.codec(&mut block2);

        assert_eq!(
            block1, block2,
            "Same password should produce same ciphertext"
        );
    }

    #[test]
    fn test_different_passwords_different_ciphertext() {
        let mut cc1 = CuaimaCrypt::new();
        cc1.password("Password1").unwrap();

        let mut cc2 = CuaimaCrypt::new();
        cc2.password("Password2").unwrap();

        let mut block1 = [42i64, 84];
        let mut block2 = [42i64, 84];

        cc1.codec(&mut block1);
        cc2.codec(&mut block2);

        assert_ne!(
            block1, block2,
            "Different passwords should produce different ciphertext"
        );
    }

    #[test]
    fn test_reset_enables_re_encryption() {
        let mut cc = CuaimaCrypt::new();
        cc.password("ResetTest2024").unwrap();

        let mut block1 = [100i64, 200];
        cc.codec(&mut block1);

        cc.reset();

        let mut block2 = [100i64, 200];
        cc.codec(&mut block2);

        assert_eq!(
            block1, block2,
            "After reset, same plaintext should produce same ciphertext"
        );
    }

    #[test]
    fn test_get_bit() {
        // Bit 63 (MSB) of 0x8000000000000000 should be 1
        assert_eq!(CuaimaCrypt::get_bit(i64::MIN, 63), 1);
        // Bit 0 (LSB) of 1 should be 1
        assert_eq!(CuaimaCrypt::get_bit(1, 0), 1);
        // Bit 1 of 1 should be 0
        assert_eq!(CuaimaCrypt::get_bit(1, 1), 0);
    }

    #[test]
    fn test_get_8_bits() {
        let val = 0x0123456789ABCDEF_u64 as i64;
        // pos=0: shift=56, extracts least significant byte
        assert_eq!(CuaimaCrypt::get_8_bits(val, 0), 0xEF);
        // pos=8: shift=48, extracts second byte from right
        assert_eq!(CuaimaCrypt::get_8_bits(val, 8), 0xCD);
        // pos=56: shift=0, extracts most significant byte
        assert_eq!(CuaimaCrypt::get_8_bits(val, 56), 0x01);
    }

    #[test]
    fn test_interleaving_de_interleaving_roundtrip() {
        let original: [i64; 2] = [0x0123456789ABCDEF_u64 as i64, 0xFEDCBA9876543210_u64 as i64];
        let mut block = original;

        CuaimaCrypt::interleaving(&mut block);
        assert_ne!(block, original, "Interleaving should change block");

        CuaimaCrypt::de_interleaving(&mut block);
        assert_eq!(block, original, "DeInterleaving should restore original");
    }

    #[test]
    fn test_cross_byte_operations() {
        // Test all 4 cross byte operations are invertible with themselves
        // (they're not necessarily self-inverse, but they should be deterministic)
        let original: [i64; 2] = [0x0123456789ABCDEF_u64 as i64, 0xFEDCBA9876543210_u64 as i64];

        for op in 0..4 {
            let mut block = original;
            CuaimaCrypt::cross_byte(op, &mut block);
            assert_ne!(block, original, "CrossByte({}) should modify the block", op);
        }
    }

    #[test]
    fn test_transpose_left_right_roundtrip() {
        let val = 0x0123456789ABCDEF_u64 as i64;
        let transposed = CuaimaCrypt::transpose_left(val);
        let restored = CuaimaCrypt::transpose_right(transposed);
        assert_eq!(
            restored, val,
            "TransposeRight(TransposeLeft(x)) should equal x"
        );
    }

    #[test]
    fn test_rand_distribuidor_is_permutation() {
        let mut sparker = PasswordSparker::new("TestDistrib");
        let mut kaos = KaosRand::from_sparker(&mut sparker as &mut dyn Sparker);

        let result = CuaimaCrypt::rand_distribuidor(&mut kaos, 10);
        assert_eq!(result.len(), 10);

        // Check it's a permutation: each value 0..9 appears exactly once
        let mut sorted = result.clone();
        sorted.sort();
        let expected: Vec<i32> = (0..10).collect();
        assert_eq!(
            sorted, expected,
            "RandDistribuidor should produce a permutation"
        );
    }

    #[test]
    fn test_custom_num_rakes_roundtrip() {
        for num in [2, 5, 16] {
            let mut encoder = CuaimaCrypt::with_num_rakes(num).unwrap();
            encoder.password("CustomRakes2024").unwrap();

            let mut decoder = CuaimaCrypt::with_num_rakes(num).unwrap();
            decoder.password("CustomRakes2024").unwrap();

            let original = [0xDEADBEEFCAFEBABE_u64 as i64, 0x1234567890ABCDEF_u64 as i64];
            let mut block = original;

            encoder.codec(&mut block);
            decoder.decodec(&mut block);
            assert_eq!(block, original, "Roundtrip failed for {} rakes", num);
        }
    }

    // ── BUG-001 regression tests (migrated from tests/bug001_regression.rs) ──

    /// Verifies codec/decodec roundtrip for each known-bad password across
    /// multiple plaintext values.
    ///
    /// BUG-001: encoder and decoder diverge because KaosRand's internal
    /// MersenneTwister is seeded with system time when jump == 0.
    #[test]
    fn bug001_roundtrip_known_bad_passwords() {
        for password in BAD_PASSWORDS {
            for (i, &plaintext) in PLAINTEXTS.iter().enumerate() {
                let mut encoder = CuaimaCrypt::new();
                encoder.password(password).unwrap();
                let mut block = plaintext;
                encoder.codec(&mut block);

                let mut decoder = CuaimaCrypt::new();
                decoder.password(password).unwrap();
                decoder.decodec(&mut block);

                assert_eq!(
                    block, plaintext,
                    "Roundtrip failed for password '{}', plaintext[{}]",
                    password, i
                );
            }
        }
    }

    /// Verifies that two independent encoder instances initialized with the
    /// same bad password produce identical ciphertext.
    ///
    /// BUG-001: each instance seeds MersenneTwister with a different system
    /// time, causing completely different cipher states.
    #[test]
    fn bug001_deterministic_ciphertext_known_bad_passwords() {
        for password in BAD_PASSWORDS {
            let plaintext: [i64; 2] = [0x0102030405060708, 0x090A0B0C0D0E0F10];

            let mut enc1 = CuaimaCrypt::new();
            enc1.password(password).unwrap();
            let mut block1 = plaintext;
            enc1.codec(&mut block1);

            let mut enc2 = CuaimaCrypt::new();
            enc2.password(password).unwrap();
            let mut block2 = plaintext;
            enc2.codec(&mut block2);

            assert_eq!(
                block1, block2,
                "Ciphertext diverged for password '{}'",
                password
            );
        }
    }

    /// Verifies that multiple consecutive blocks round-trip correctly with
    /// bad passwords. SeedHopping permutes state after each block, so if
    /// the first block is wrong, all subsequent blocks are also wrong.
    #[test]
    fn bug001_multi_block_sequential_roundtrip() {
        for password in BAD_PASSWORDS {
            let mut encoder = CuaimaCrypt::new();
            encoder.password(password).unwrap();

            let mut decoder = CuaimaCrypt::new();
            decoder.password(password).unwrap();

            for block_idx in 0..10u64 {
                let plaintext: [i64; 2] = [block_idx as i64, !(block_idx as i64)];
                let mut block = plaintext;
                encoder.codec(&mut block);
                decoder.decodec(&mut block);
                assert_eq!(
                    block, plaintext,
                    "Multi-block roundtrip failed for password '{}', block {}",
                    password, block_idx
                );
            }
        }
    }

    /// Verifies roundtrip for bad passwords with various rake counts.
    ///
    /// The bug is in KaosRand initialization (shared across all rake counts),
    /// so any rake count that uses `KaosRand::from_sparker` is affected.
    #[test]
    fn bug001_bad_passwords_with_custom_rake_counts() {
        let rake_counts = [2, 5, 16];
        for password in BAD_PASSWORDS {
            for &rakes in &rake_counts {
                let mut encoder = CuaimaCrypt::with_num_rakes(rakes).unwrap();
                encoder.password(password).unwrap();

                let mut decoder = CuaimaCrypt::with_num_rakes(rakes).unwrap();
                decoder.password(password).unwrap();

                let plaintext: [i64; 2] = [0x0102030405060708, 0x090A0B0C0D0E0F10];
                let mut block = plaintext;
                encoder.codec(&mut block);
                decoder.decodec(&mut block);

                assert_eq!(
                    block, plaintext,
                    "Roundtrip failed for password '{}', rakes={}",
                    password, rakes
                );
            }
        }
    }

    /// Fuzzes 1000 passwords and verifies 0% roundtrip failure rate.
    ///
    /// Before the fix, approximately 4% (~40 out of 1000) fail silently.
    /// After the fix, all must pass.
    #[test]
    fn bug001_roundtrip_zero_failure_rate_fuzz() {
        let plaintext: [i64; 2] = [0x0102030405060708, 0x090A0B0C0D0E0F10];

        // Build password set: known bad + diverse formats
        let mut passwords: Vec<String> = Vec::with_capacity(1050);
        passwords.extend(BAD_PASSWORDS.iter().map(|s| s.to_string()));
        for i in 0..500 {
            passwords.push(format!("TestPassword_{}", i));
        }
        for i in 0..500 {
            passwords.push(format!("Pwd{}_check", i));
        }
        let num_passwords = passwords.len();

        // Phase 1: encode all blocks
        let ciphertexts: Vec<[i64; 2]> = passwords
            .iter()
            .map(|pw| {
                let mut encoder = CuaimaCrypt::new();
                encoder.password(pw).unwrap();
                let mut block = plaintext;
                encoder.codec(&mut block);
                block
            })
            .collect();

        // Phase 2: decode all blocks (time gap from Phase 1)
        let mut failures = Vec::new();
        for (i, pw) in passwords.iter().enumerate() {
            let mut decoder = CuaimaCrypt::new();
            decoder.password(pw).unwrap();
            let mut block = ciphertexts[i];
            decoder.decodec(&mut block);

            if block != plaintext {
                failures.push(pw.clone());
            }
        }

        assert!(
            failures.is_empty(),
            "Roundtrip failed for {} out of {} passwords ({:.1}%): {:?}",
            failures.len(),
            num_passwords,
            failures.len() as f64 / num_passwords as f64 * 100.0,
            &failures[..failures.len().min(10)]
        );
    }
}
