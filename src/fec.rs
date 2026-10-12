//! Datagram-level sliding-window forward error correction.
//!
//! This module contains only bounded arithmetic and state machines.  Physical
//! framing, authentication, and control-stream feedback stay in their
//! respective layers.

use std::{collections::VecDeque, sync::Arc};

pub const MAX_REPAIR_WINDOW: usize = 256;
pub const DECODER_WIDTH: usize = 512;
pub const WINDOW_CAPACITY: usize = 64;
pub const MAX_RATE: f64 = 8.0;
pub const MAX_RATE_MILLI: u16 = 8_000;
pub const TARGET_RESIDUAL: f64 = 1e-3;
/// Bound the repair burst that either side can accumulate or admit.
pub const MAX_REPAIR_CREDIT_MILLI: u64 = DECODER_WIDTH as u64 * 1_000;

pub(crate) const RECOVERY_PROBE_MARKER: &[u8] = b"tinect-fec-probe\0";

const MIN_CODED_LOSS: f64 = 0.005;
const MIN_REPORT_SAMPLES: u32 = 128;
const WINDOW_CHAINING: f64 = 2.5;
const RATE_INCREASE_STEP_MILLI: u16 = 1_000;
const RATE_DECREASE_STEP_MILLI: u16 = 500;
pub const MAX_SYMBOL_BYTES: usize = u16::MAX as usize + 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FecReport {
    pub report_id: u64,
    pub samples: u32,
    pub loss_ppm: u32,
    pub burst_milli: u16,
}

pub(crate) fn report_is_valid(report: FecReport) -> bool {
    report.samples >= MIN_REPORT_SAMPLES
        && report.loss_ppm <= 1_000_000
        && report.burst_milli >= 1_000
}

pub(crate) fn report_is_saturated_loss(report: FecReport) -> bool {
    report_is_valid(report) && report.loss_ppm == 1_000_000
}

pub fn recovery_probe_frame() -> Vec<u8> {
    let mut frame = vec![0; crate::crypto::FRAME_OVERHEAD];
    frame[..RECOVERY_PROBE_MARKER.len()].copy_from_slice(RECOVERY_PROBE_MARKER);
    frame
}

pub fn is_recovery_probe(frame: &[u8]) -> bool {
    frame.starts_with(RECOVERY_PROBE_MARKER)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceSymbol {
    pub transmission_sequence: u32,
    pub esi: u32,
    pub frame: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepairSymbol {
    pub transmission_sequence: u32,
    pub rid: u32,
    pub first_esi: u32,
    pub symbol_count: u16,
    pub vector: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FecError {
    FrameTooShort,
    FrameTooLarge,
    SymbolTooLarge,
    InvalidRepairCount,
    RepairVectorTooLarge,
    RepairWindowJump,
    InvalidReport,
}

#[derive(Clone, Copy)]
struct Field;

impl Field {
    fn add(a: u8, b: u8) -> u8 {
        a ^ b
    }

    fn mul(a: u8, b: u8) -> u8 {
        let mut a = a;
        let mut b = b;
        let mut out = 0;
        while b != 0 {
            if b & 1 != 0 {
                out ^= a;
            }
            let carry = a & 0x80 != 0;
            a <<= 1;
            if carry {
                a ^= 0x1d;
            }
            b >>= 1;
        }
        out
    }

    fn pow(mut value: u8, mut exponent: u16) -> u8 {
        let mut out = 1;
        while exponent != 0 {
            if exponent & 1 != 0 {
                out = Self::mul(out, value);
            }
            value = Self::mul(value, value);
            exponent >>= 1;
        }
        out
    }

    fn inv(value: u8) -> u8 {
        assert_ne!(value, 0);
        Self::pow(value, 254)
    }
}

/// Generate a deterministic non-zero coefficient for a repair row.
pub fn coefficient(repair_id: u32, index: u32) -> u8 {
    let mut x = repair_id
        .wrapping_mul(2_654_435_761)
        .wrapping_add(index.wrapping_mul(2_246_822_519));
    x ^= x >> 15;
    x = x.wrapping_mul(2_654_435_761);
    x ^= x >> 13;
    x = x.wrapping_mul(2_246_822_519);
    x ^= x >> 16;
    (x % 255) as u8 + 1
}

fn symbol(frame: &[u8]) -> Result<Vec<u8>, FecError> {
    if frame.len() < crate::crypto::FRAME_OVERHEAD {
        return Err(FecError::FrameTooShort);
    }
    let len = u16::try_from(frame.len()).map_err(|_| FecError::FrameTooLarge)?;
    let mut out = Vec::with_capacity(frame.len() + 2);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(frame);
    Ok(out)
}

fn add_scaled(dst: &mut [u8], src: &[u8], scale: u8) {
    for (dst, src) in dst.iter_mut().zip(src.iter().copied()) {
        *dst = Field::add(*dst, Field::mul(src, scale));
    }
}

fn sequence_distance(base: u32, value: u32) -> u32 {
    value.wrapping_sub(base)
}

#[derive(Debug, Clone)]
pub struct WindowEncoder {
    window: VecDeque<(u32, Vec<u8>)>,
    next_esi: u32,
    next_transmission_sequence: u32,
    next_repair_id: u32,
    credit_milli: u64,
    rate_milli: u16,
    tail_pending: bool,
    burst_source_count: usize,
}

impl WindowEncoder {
    pub fn new(rate_milli: u16) -> Self {
        Self {
            window: VecDeque::with_capacity(WINDOW_CAPACITY),
            next_esi: 0,
            next_transmission_sequence: 0,
            next_repair_id: 0,
            credit_milli: 0,
            rate_milli: rate_milli.min(MAX_RATE_MILLI),
            tail_pending: false,
            burst_source_count: 0,
        }
    }

    pub fn rate_milli(&self) -> u16 {
        self.rate_milli
    }

    pub fn set_rate_milli(&mut self, rate_milli: u16) {
        self.rate_milli = rate_milli.min(MAX_RATE_MILLI);
        if self.rate_milli == 0 {
            self.credit_milli = 0;
        }
    }

    pub fn has_pending_tail(&self) -> bool {
        self.tail_pending && !self.window.is_empty()
    }

    #[cfg(test)]
    pub(crate) fn credit_milli_for_test(&self) -> u64 {
        self.credit_milli
    }

    /// Generate an end-of-burst repair block from the current burst budget.
    ///
    /// Tail repairs never create additional repair credit.  They only drain
    /// credit restored for locally unsent repairs, and are limited to the
    /// source symbols in the current burst rather than the whole sliding
    /// window.
    pub fn flush_tail(&mut self) -> Vec<RepairSymbol> {
        if !self.tail_pending || self.window.is_empty() {
            return Vec::new();
        }
        let burst_len = self.burst_source_count.min(self.window.len());
        let repair_count = (self.credit_milli / 1_000).min(burst_len as u64) as usize;
        self.tail_pending = false;
        self.credit_milli = self
            .credit_milli
            .saturating_sub((repair_count as u64) * 1_000);
        (0..repair_count)
            .map(|_| self.make_repair(burst_len))
            .collect()
    }

    pub(crate) fn finish_tail(&mut self) {
        self.tail_pending = false;
        self.burst_source_count = 0;
    }

    /// Keep the sequence space contiguous after locally dropping repairs.
    ///
    /// The source has already been sent, so its state remains committed.  Any
    /// repair after the last successfully sent one was never observable by a
    /// peer and must not create a phantom loss sample.
    pub(crate) fn rollback_unsent_repairs(
        &mut self,
        source_transmission_sequence: u32,
        sent_repairs: usize,
        total_repairs: usize,
    ) {
        self.restore_tail_repairs(total_repairs.saturating_sub(sent_repairs));
        self.truncate_transmission_sequence(
            source_transmission_sequence
                .wrapping_add(1)
                .wrapping_add(sent_repairs as u32),
        );
    }

    pub(crate) fn truncate_transmission_sequence(&mut self, next: u32) {
        self.next_transmission_sequence = next;
    }

    pub(crate) fn restore_tail_repairs(&mut self, repair_count: usize) {
        if repair_count == 0 {
            return;
        }
        self.add_credit((repair_count as u64).saturating_mul(1_000));
        self.tail_pending = true;
    }

    fn add_credit(&mut self, credit_milli: u64) {
        self.credit_milli = self
            .credit_milli
            .saturating_add(credit_milli)
            .min(MAX_REPAIR_CREDIT_MILLI);
    }

    pub fn push(&mut self, frame: &[u8]) -> Result<(SourceSymbol, Vec<RepairSymbol>), FecError> {
        let vector = symbol(frame)?;
        if vector.len() > MAX_SYMBOL_BYTES {
            return Err(FecError::SymbolTooLarge);
        }
        let esi = self.next_esi;
        self.next_esi = self.next_esi.wrapping_add(1);
        let transmission_sequence = self.next_transmission_sequence;
        self.next_transmission_sequence = self.next_transmission_sequence.wrapping_add(1);
        self.window.push_back((esi, vector));
        while self.window.len() > WINDOW_CAPACITY {
            self.window.pop_front();
        }
        if self.tail_pending {
            self.burst_source_count = self
                .burst_source_count
                .saturating_add(1)
                .min(WINDOW_CAPACITY);
        } else {
            self.burst_source_count = 1;
        }
        self.tail_pending = true;

        let source = SourceSymbol {
            transmission_sequence,
            esi,
            frame: frame.to_vec(),
        };

        self.add_credit(u64::from(self.rate_milli));
        let mut repairs = Vec::new();
        while self.credit_milli >= 1_000 {
            self.credit_milli -= 1_000;
            repairs.push(self.make_repair(self.window.len()));
        }
        Ok((source, repairs))
    }

    fn make_repair(&mut self, source_count: usize) -> RepairSymbol {
        let rid = self.next_repair_id;
        self.next_repair_id = self.next_repair_id.wrapping_add(1);
        let start = self.window.len().saturating_sub(source_count);
        let first_esi = self
            .window
            .get(start)
            .map(|entry| entry.0)
            .expect("repair requires a non-empty window");
        let symbol_count = u16::try_from(self.window.len() - start).expect("window bounded");
        let vector = encode_repair(
            rid,
            self.window.iter().skip(start).map(|(_, vector)| vector),
        );
        let transmission_sequence = self.next_transmission_sequence;
        self.next_transmission_sequence = self.next_transmission_sequence.wrapping_add(1);
        RepairSymbol {
            transmission_sequence,
            rid,
            first_esi,
            symbol_count,
            vector,
        }
    }
}

fn encode_repair<'a>(repair_id: u32, vectors: impl Iterator<Item = &'a Vec<u8>>) -> Vec<u8> {
    let vectors = vectors.collect::<Vec<_>>();
    let length = vectors.iter().map(|vector| vector.len()).max().unwrap_or(0);
    let mut out = vec![0; length];
    for (index, vector) in vectors.iter().enumerate() {
        add_scaled(&mut out, vector, coefficient(repair_id, index as u32));
    }
    out
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeliveryOrigin {
    Source,
    Recovered,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeliveredFrame {
    pub esi: u32,
    pub frame: Vec<u8>,
    pub origin: DeliveryOrigin,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Delivery {
    pub frames: Vec<DeliveredFrame>,
    pub lost: Vec<u32>,
    pub discarded: bool,
}

#[derive(Debug, Clone, Default)]
struct DecoderSlot {
    esi: u32,
    vector: Arc<Vec<u8>>,
    live: bool,
    known: bool,
}

#[derive(Debug, Clone)]
struct Equation {
    pivot: u32,
    coefficients: Arc<Vec<u8>>,
    vector: Arc<Vec<u8>>,
}

#[derive(Debug, Clone)]
pub struct WindowDecoder {
    slots: Vec<DecoderSlot>,
    lo: u32,
    high: u32,
    origin: u32,
    started: bool,
    rows: Vec<Equation>,
}

impl Default for WindowDecoder {
    fn default() -> Self {
        Self {
            slots: (0..DECODER_WIDTH).map(|_| DecoderSlot::default()).collect(),
            lo: 0,
            high: 0,
            origin: 0,
            started: false,
            rows: Vec::with_capacity(DECODER_WIDTH),
        }
    }
}

impl WindowDecoder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn width(&self) -> usize {
        self.slots.len()
    }

    pub fn source(&mut self, esi: u32, frame: &[u8]) -> Result<Delivery, FecError> {
        self.source_inner(esi, Arc::new(symbol(frame)?))
    }

    fn source_inner(&mut self, esi: u32, vector: Arc<Vec<u8>>) -> Result<Delivery, FecError> {
        let mut out = Delivery::default();
        if !self.admit(esi, &mut out)? {
            out.discarded = true;
            return Ok(out);
        }
        self.witness(esi);
        let index = self.index(esi);
        if self.slots[index].live && self.slots[index].esi == esi && self.slots[index].known {
            return Ok(out);
        }
        self.substitute(esi, vector, DeliveryOrigin::Source, &mut out);
        self.harvest(&mut out);
        Ok(out)
    }

    pub fn repair(
        &mut self,
        rid: u32,
        first_esi: u32,
        symbol_count: u16,
        vector: &[u8],
    ) -> Result<Delivery, FecError> {
        let count = usize::from(symbol_count);
        if count == 0 || count > MAX_REPAIR_WINDOW {
            return Err(FecError::InvalidRepairCount);
        }
        if vector.is_empty() || vector.len() > MAX_SYMBOL_BYTES {
            return Err(FecError::RepairVectorTooLarge);
        }
        let mut candidate = self.clone();
        let delivery = candidate.repair_inner(rid, first_esi, symbol_count, vector)?;
        if delivery.discarded {
            return Ok(Delivery {
                discarded: true,
                ..Delivery::default()
            });
        }
        *self = candidate;
        Ok(delivery)
    }

    fn repair_inner(
        &mut self,
        rid: u32,
        first_esi: u32,
        symbol_count: u16,
        vector: &[u8],
    ) -> Result<Delivery, FecError> {
        let count = usize::from(symbol_count);
        let end = first_esi.wrapping_add(count as u32 - 1);
        let mut out = Delivery::default();
        if !self.admit(end, &mut out)? {
            out.discarded = true;
            return Ok(out);
        }
        self.witness(first_esi);
        if is_before(first_esi, self.lo) {
            out.discarded = true;
            return Ok(out);
        }

        let mut coefficients = vec![0; self.slots.len()];
        for index in 0..count {
            let esi = first_esi.wrapping_add(index as u32);
            if !is_before(esi, self.lo) && is_before(esi, self.high) {
                coefficients[self.index(esi)] = coefficient(rid, index as u32);
            }
        }
        if coefficients.iter().all(|value| *value == 0) {
            out.discarded = true;
            return Ok(out);
        }
        self.insert_row(coefficients, vector.to_vec(), &mut out);
        Ok(out)
    }

    /// Check whether a repair would be accepted by the decoder window without
    /// changing decoder state.  The carrier uses this before charging repair
    /// credit so stale or out-of-window repairs cannot advance admission.
    pub fn repair_window_admissible(
        &self,
        first_esi: u32,
        symbol_count: u16,
    ) -> Result<bool, FecError> {
        let count = usize::from(symbol_count);
        if count == 0 || count > MAX_REPAIR_WINDOW {
            return Err(FecError::InvalidRepairCount);
        }
        let end = first_esi.wrapping_add(count as u32 - 1);
        if !self.started {
            return Ok(true);
        }
        if is_before(end, self.lo) {
            return Ok(false);
        }

        let new_lo = if is_before(self.high, end.wrapping_add(1)) {
            let advance = sequence_distance(self.high, end.wrapping_add(1));
            if advance > (MAX_REPAIR_WINDOW * 4) as u32 {
                return Ok(true);
            }
            end.wrapping_add(1).wrapping_sub(self.slots.len() as u32)
        } else {
            self.lo
        };
        Ok(!is_before(first_esi, new_lo))
    }

    fn index(&self, esi: u32) -> usize {
        (esi as usize) & (self.slots.len() - 1)
    }

    fn admit(&mut self, esi: u32, out: &mut Delivery) -> Result<bool, FecError> {
        if !self.started {
            self.started = true;
            self.origin = esi;
            self.high = esi.wrapping_add(1);
            self.lo = self.high.wrapping_sub(self.slots.len() as u32);
            return Ok(true);
        }
        if is_before(esi, self.lo) {
            return Ok(false);
        }
        if is_before(self.high, esi.wrapping_add(1)) {
            let advance = sequence_distance(self.high, esi.wrapping_add(1));
            if advance > (MAX_REPAIR_WINDOW * 4) as u32 {
                self.reset_window(esi, out);
                return Ok(true);
            }
            let new_high = esi.wrapping_add(1);
            let new_lo = new_high.wrapping_sub(self.slots.len() as u32);
            let old_lo = self.lo;
            let walked = sequence_distance(old_lo, self.high).min(self.slots.len() as u32);
            for offset in 0..walked {
                let old_esi = old_lo.wrapping_add(offset);
                if is_before(old_esi, new_lo) {
                    self.evict(old_esi, out);
                }
            }
            self.high = new_high;
            self.lo = new_lo;
        }
        Ok(true)
    }

    fn reset_window(&mut self, esi: u32, out: &mut Delivery) {
        for slot in &self.slots {
            if slot.live && !slot.known && !is_before(slot.esi, self.origin) {
                out.lost.push(slot.esi);
            }
        }
        for slot in &mut self.slots {
            *slot = DecoderSlot::default();
        }
        self.rows.clear();
        self.started = true;
        self.origin = esi;
        self.high = esi.wrapping_add(1);
        self.lo = self.high.wrapping_sub(self.slots.len() as u32);
    }

    fn witness(&mut self, esi: u32) {
        if self.started && is_before(esi, self.origin) && !is_before(esi, self.lo) {
            self.origin = esi;
        }
    }

    fn evict(&mut self, esi: u32, out: &mut Delivery) {
        let index = self.index(esi);
        let slot = &mut self.slots[index];
        let held = slot.live && slot.esi == esi;
        if !(held && slot.known) && !is_before(esi, self.origin) {
            out.lost.push(esi);
        }
        if held {
            *slot = DecoderSlot::default();
        }
        // A row that still references an evicted unknown is no longer a valid
        // equation. Removing just that coefficient would turn an equation
        // over a wider window into a different equation and could produce a
        // false recovery after a window slide.
        self.rows.retain(|row| row.coefficients[index] == 0);
    }

    fn insert_row(&mut self, mut coefficients: Vec<u8>, mut vector: Vec<u8>, out: &mut Delivery) {
        for offset in 0..self.slots.len() {
            let esi = self.lo.wrapping_add(offset as u32);
            let index = self.index(esi);
            let scale = coefficients[index];
            if scale == 0 {
                continue;
            }
            let slot = &self.slots[index];
            if slot.live && slot.esi == esi && slot.known {
                ensure_len(&mut vector, slot.vector.len());
                add_scaled(&mut vector, &slot.vector, scale);
                coefficients[index] = 0;
            }
        }
        for row in &self.rows {
            let scale = coefficients[self.index(row.pivot)];
            if scale == 0 {
                continue;
            }
            ensure_len(&mut vector, row.vector.len());
            add_scaled(&mut vector, &row.vector, scale);
            for (index, coefficient) in coefficients.iter_mut().enumerate() {
                *coefficient = Field::add(*coefficient, Field::mul(scale, row.coefficients[index]));
            }
        }
        let Some((pivot, pivot_value)) = leading(&coefficients, self.lo, self.slots.len()) else {
            out.discarded = true;
            return;
        };
        let inverse = Field::inv(pivot_value);
        for value in &mut coefficients {
            *value = Field::mul(*value, inverse);
        }
        for value in &mut vector {
            *value = Field::mul(*value, inverse);
        }
        let pivot_index = self.index(pivot);
        let new_row = Equation {
            pivot,
            coefficients: Arc::new(coefficients),
            vector: Arc::new(vector),
        };
        for row in &mut self.rows {
            let scale = row.coefficients[pivot_index];
            if scale == 0 {
                continue;
            }
            let row_vector = Arc::make_mut(&mut row.vector);
            ensure_len(row_vector, new_row.vector.len());
            add_scaled(row_vector, new_row.vector.as_slice(), scale);
            let row_coefficients = Arc::make_mut(&mut row.coefficients);
            for (index, coefficient) in row_coefficients.iter_mut().enumerate() {
                *coefficient =
                    Field::add(*coefficient, Field::mul(scale, new_row.coefficients[index]));
            }
        }
        if self.rows.len() == DECODER_WIDTH {
            self.rows.remove(0);
        }
        self.rows.push(new_row);
        self.harvest(out);
    }

    fn harvest(&mut self, out: &mut Delivery) {
        loop {
            let Some(index) = self
                .rows
                .iter()
                .position(|row| count_nonzero(&row.coefficients) == 1)
            else {
                return;
            };
            let row = self.rows.remove(index);
            let Some((esi, pivot_value)) = leading(&row.coefficients, self.lo, self.slots.len())
            else {
                continue;
            };
            let inverse = Field::inv(pivot_value);
            let mut vector = Arc::try_unwrap(row.vector).unwrap_or_else(|vector| (*vector).clone());
            for value in &mut vector {
                *value = Field::mul(*value, inverse);
            }
            self.substitute(esi, Arc::new(vector), DeliveryOrigin::Recovered, out);
        }
    }

    fn substitute(
        &mut self,
        esi: u32,
        vector: Arc<Vec<u8>>,
        origin: DeliveryOrigin,
        out: &mut Delivery,
    ) {
        let Some(frame) = decode_symbol(vector.as_slice()) else {
            if matches!(origin, DeliveryOrigin::Recovered) {
                out.discarded = true;
            }
            return;
        };
        let index = self.index(esi);
        if self.slots[index].live && self.slots[index].esi == esi && self.slots[index].known {
            return;
        }
        self.slots[index] = DecoderSlot {
            esi,
            vector: vector.clone(),
            live: true,
            known: true,
        };
        out.frames.push(DeliveredFrame { esi, frame, origin });
        for row in &mut self.rows {
            let scale = row.coefficients[index];
            if scale == 0 {
                continue;
            }
            let row_vector = Arc::make_mut(&mut row.vector);
            ensure_len(row_vector, vector.len());
            add_scaled(row_vector, vector.as_slice(), scale);
            Arc::make_mut(&mut row.coefficients)[index] = 0;
        }
    }
}

fn decode_symbol(vector: &[u8]) -> Option<Vec<u8>> {
    let length = vector
        .get(..2)
        .map(|bytes| usize::from(u16::from_be_bytes([bytes[0], bytes[1]])))?;
    if length < crate::crypto::FRAME_OVERHEAD || length + 2 > vector.len() {
        return None;
    }
    Some(vector[2..length + 2].to_vec())
}

fn ensure_len(vector: &mut Vec<u8>, length: usize) {
    if vector.len() < length {
        vector.resize(length, 0);
    }
}

fn count_nonzero(coefficients: &[u8]) -> usize {
    coefficients.iter().filter(|value| **value != 0).count()
}

fn leading(coefficients: &[u8], lo: u32, width: usize) -> Option<(u32, u8)> {
    (0..width).find_map(|offset| {
        let esi = lo.wrapping_add(offset as u32);
        let index = (esi as usize) & (width - 1);
        (coefficients[index] != 0).then_some((esi, coefficients[index]))
    })
}

fn is_before(value: u32, base: u32) -> bool {
    value.wrapping_sub(base) >= 0x8000_0000
}

const LOSS_RING_SIZE: usize = 1024;
const REORDER_TOLERANCE: u32 = 8;
const MAX_DECIDED_PER_ARRIVAL: u32 = (LOSS_RING_SIZE * 8) as u32;

#[derive(Debug)]
pub struct LossEstimator {
    arrived: [bool; LOSS_RING_SIZE],
    next: u32,
    highest: u32,
    started: bool,
    reordered: u64,
    decided: u64,
    samples: u64,
    lost: u64,
    burst_sum: u64,
    burst_events: u64,
    current_burst: u64,
    since_report: u64,
    next_report_id: u64,
    pending_report: Option<FecReport>,
    latest_report: Option<FecReport>,
}

impl Default for LossEstimator {
    fn default() -> Self {
        Self {
            arrived: [false; LOSS_RING_SIZE],
            next: 0,
            highest: 0,
            started: false,
            reordered: 0,
            decided: 0,
            samples: 0,
            lost: 0,
            burst_sum: 0,
            burst_events: 0,
            current_burst: 0,
            since_report: 0,
            next_report_id: 1,
            pending_report: None,
            latest_report: None,
        }
    }
}

impl LossEstimator {
    pub fn observe(&mut self, sequence: u32) {
        if !self.started {
            self.started = true;
            self.next = sequence;
            self.highest = sequence;
            self.arrived[(sequence as usize) & (LOSS_RING_SIZE - 1)] = true;
            return;
        }
        if is_before(sequence, self.next) {
            if self.decided != 0
                || sequence_distance(sequence, self.highest) >= LOSS_RING_SIZE as u32
            {
                self.reordered = self.reordered.saturating_add(1);
                return;
            }
            self.next = sequence;
        }
        if is_before(self.highest, sequence) {
            self.highest = sequence;
        }
        if sequence_distance(self.next, self.highest) > MAX_DECIDED_PER_ARRIVAL {
            self.arrived = [false; LOSS_RING_SIZE];
            self.next = sequence;
            self.highest = sequence;
            self.arrived[(sequence as usize) & (LOSS_RING_SIZE - 1)] = true;
            return;
        }
        let current_is_in_ring = sequence_distance(self.next, self.highest) < LOSS_RING_SIZE as u32;
        if current_is_in_ring {
            self.arrived[(sequence as usize) & (LOSS_RING_SIZE - 1)] = true;
        }
        while sequence_distance(self.next, self.highest) >= LOSS_RING_SIZE as u32 {
            self.decide();
        }
        if !current_is_in_ring {
            self.arrived[(sequence as usize) & (LOSS_RING_SIZE - 1)] = true;
        }
        while sequence_distance(self.next, self.highest) >= REORDER_TOLERANCE {
            self.decide();
        }
    }

    pub fn reordered(&self) -> u64 {
        self.reordered
    }

    pub fn decided(&self) -> u64 {
        self.decided
    }

    fn decide(&mut self) {
        let index = (self.next as usize) & (LOSS_RING_SIZE - 1);
        let arrived = self.arrived[index];
        self.arrived[index] = false;
        self.next = self.next.wrapping_add(1);
        self.record(arrived);
    }

    fn record(&mut self, arrived: bool) {
        self.decided = self.decided.saturating_add(1);
        self.samples = self.samples.saturating_add(1);
        if !arrived {
            self.lost = self.lost.saturating_add(1);
            self.current_burst = self.current_burst.saturating_add(1);
        } else if self.current_burst != 0 {
            self.burst_sum = self.burst_sum.saturating_add(self.current_burst);
            self.burst_events = self.burst_events.saturating_add(1);
            self.current_burst = 0;
        }
        self.since_report = self.since_report.saturating_add(1);
        if self.since_report >= 128 {
            self.make_report();
        }
    }

    fn make_report(&mut self) {
        if self.samples == 0 {
            return;
        }
        if self.current_burst != 0 {
            self.burst_sum = self.burst_sum.saturating_add(self.current_burst);
            self.burst_events = self.burst_events.saturating_add(1);
            self.current_burst = 0;
        }
        let total = self.samples.max(1);
        let loss_ppm = self.lost.saturating_mul(1_000_000) / total;
        let burst_milli = if self.burst_events == 0 {
            1_000
        } else {
            self.burst_sum
                .saturating_mul(1_000)
                .checked_div(self.burst_events)
                .unwrap_or(0)
                .clamp(1_000, u64::from(u16::MAX))
        };
        let report = FecReport {
            report_id: self.next_report_id,
            samples: total.min(u64::from(u32::MAX)) as u32,
            loss_ppm: loss_ppm.min(u64::from(u32::MAX)) as u32,
            burst_milli: burst_milli as u16,
        };
        self.latest_report = Some(report);
        self.pending_report = Some(report);
        self.next_report_id = self.next_report_id.wrapping_add(1).max(1);
        self.since_report = 0;
        self.samples = 0;
        self.lost = 0;
        self.burst_sum = 0;
        self.burst_events = 0;
    }

    pub fn take_report(&mut self) -> Option<FecReport> {
        self.pending_report.take()
    }

    pub fn latest_report(&self) -> Option<FecReport> {
        self.latest_report
    }

    pub fn requeue_report(&mut self, report: FecReport) {
        if self
            .pending_report
            .is_none_or(|current| current.report_id < report.report_id)
        {
            self.pending_report = Some(report);
        }
    }
}

pub fn window_rate_milli(capacity: usize, report: FecReport, configured_cap: u16) -> Option<u16> {
    if capacity == 0 || !report_is_valid(report) {
        return None;
    }
    let loss = f64::from(report.loss_ppm) / 1_000_000.0;
    if loss < MIN_CODED_LOSS {
        return Some(0);
    }
    // No FEC parity can reach a receiver that observes no arrivals. Treat a
    // saturated report as unavailable evidence and let Link health/recovery
    // handle the outage instead of increasing traffic into it.
    if loss >= 1.0 {
        return None;
    }
    let burst = (f64::from(report.burst_milli) / 1_000.0).max(1.0);
    let arrival = 1.0 - loss;
    if arrival <= f64::EPSILON {
        return None;
    }
    let effective = (capacity as f64 * WINDOW_CHAINING).ceil() as usize;
    let mut low = effective;
    let max_total = effective.saturating_mul(1 + MAX_RATE as usize);
    let mut high = (((effective as f64 / arrival) * MAX_RATE).ceil() as usize).min(max_total);
    if binomial_tail_below(high, arrival, effective) > TARGET_RESIDUAL {
        return Some(configured_cap.min(MAX_RATE_MILLI));
    }
    while low < high {
        let middle = low + (high - low) / 2;
        if binomial_tail_below(middle, arrival, effective) <= TARGET_RESIDUAL {
            high = middle;
        } else {
            low = middle + 1;
        }
    }
    let rate = ((low.saturating_sub(effective)) as f64 / effective.max(1) as f64) * burst.min(4.0);
    Some(
        (rate * 1_000.0)
            .ceil()
            .clamp(0.0, f64::from(configured_cap.min(MAX_RATE_MILLI))) as u16,
    )
}

pub(crate) fn slew_rate_milli(current: u16, target: u16, configured_cap: u16) -> u16 {
    let cap = configured_cap.min(MAX_RATE_MILLI);
    let current = current.min(cap);
    let target = target.min(cap);
    if target > current {
        current.saturating_add(RATE_INCREASE_STEP_MILLI).min(target)
    } else {
        current.saturating_sub(RATE_DECREASE_STEP_MILLI).max(target)
    }
}

fn binomial_tail_below(n: usize, probability: f64, need: usize) -> f64 {
    if need == 0 {
        return 0.0;
    }
    if need > n || probability <= 0.0 {
        return 1.0;
    }
    if probability >= 1.0 {
        return 0.0;
    }
    let log_q = probability.ln();
    let log_p = (-probability).ln_1p();
    let log_n = factorial_log(n);
    let mut total = 0.0;
    for i in 0..need {
        let term = log_n - factorial_log(i) - factorial_log(n - i)
            + i as f64 * log_q
            + (n - i) as f64 * log_p;
        total += term.exp();
    }
    total.min(1.0)
}

fn factorial_log(value: usize) -> f64 {
    (1..=value).map(|item| (item as f64).ln()).sum()
}

#[cfg_attr(coverage_nightly, coverage(off))]
#[cfg(test)]
mod tests {
    use super::*;

    fn frame(value: u8) -> Vec<u8> {
        vec![value; crate::crypto::FRAME_OVERHEAD + 10]
    }

    #[test]
    fn coefficients_are_non_zero_and_deterministic() {
        assert_eq!(coefficient(7, 3), coefficient(7, 3));
        assert!(u32::from(coefficient(7, 3)) > 0);
        assert_ne!(coefficient(7, 3), coefficient(8, 3));
        assert_eq!(
            (0..4)
                .map(|index| coefficient(7, index))
                .collect::<Vec<_>>(),
            vec![111, 214, 19, 184]
        );
    }

    #[test]
    fn short_frames_are_rejected_with_a_specific_error() {
        assert_eq!(
            symbol(&[0; crate::crypto::FRAME_OVERHEAD - 1]),
            Err(FecError::FrameTooShort)
        );
    }

    #[test]
    fn fractional_rate_emits_a_bounded_average() {
        let mut encoder = WindowEncoder::new(500);
        let mut repairs = 0;
        for index in 0..20 {
            repairs += encoder.push(&frame(index)).unwrap().1.len();
        }
        assert_eq!(repairs, 10);
    }

    #[test]
    fn repeatedly_rejected_repairs_keep_credit_bounded() {
        let mut encoder = WindowEncoder::new(MAX_RATE_MILLI);
        let frame = frame(1);
        let max_repairs = (MAX_REPAIR_CREDIT_MILLI / 1_000) as usize;
        let pushes_to_cap = (MAX_REPAIR_CREDIT_MILLI / u64::from(MAX_RATE_MILLI)) as usize;

        for _ in 0..=pushes_to_cap {
            let (source, repairs) = encoder.push(&frame).unwrap();
            assert!(repairs.len() <= max_repairs);
            encoder.rollback_unsent_repairs(source.transmission_sequence, 0, repairs.len());
            assert!(encoder.credit_milli <= MAX_REPAIR_CREDIT_MILLI);
        }

        assert_eq!(encoder.credit_milli, MAX_REPAIR_CREDIT_MILLI);
        let (source, repairs) = encoder.push(&frame).unwrap();
        assert_eq!(repairs.len(), max_repairs);
        encoder.rollback_unsent_repairs(source.transmission_sequence, 0, repairs.len());
        assert_eq!(encoder.credit_milli, MAX_REPAIR_CREDIT_MILLI);
    }

    #[test]
    fn tail_flush_is_bounded_to_current_burst_and_credit() {
        let mut encoder = WindowEncoder::new(1_500);
        let (source, repairs) = encoder.push(&frame(1)).unwrap();
        assert_eq!(repairs.len(), 1);
        encoder.rollback_unsent_repairs(source.transmission_sequence, 0, repairs.len());
        assert!(encoder.has_pending_tail());

        let tail = encoder.flush_tail();
        assert_eq!(tail.len(), 1);
        assert_eq!(tail[0].symbol_count, 1);
        assert_eq!(
            tail[0].transmission_sequence,
            source.transmission_sequence + 1
        );
        encoder.finish_tail();
        assert!(!encoder.has_pending_tail());
        assert!(encoder.flush_tail().is_empty());
    }

    #[test]
    fn tail_flush_does_not_emit_repairs_without_credit() {
        let mut encoder = WindowEncoder::new(500);
        let mut regular_repairs = 0;
        for index in 0..WINDOW_CAPACITY {
            regular_repairs += encoder.push(&frame(index as u8)).unwrap().1.len();
        }
        assert_eq!(regular_repairs, WINDOW_CAPACITY / 2);
        assert!(encoder.has_pending_tail());
        assert!(encoder.flush_tail().is_empty());
        encoder.finish_tail();
    }

    #[test]
    fn repair_recovers_missing_source_with_different_lengths() {
        let frames = [
            frame(1),
            vec![2; crate::crypto::FRAME_OVERHEAD + 31],
            frame(3),
        ];
        let mut encoder = WindowEncoder::new(1_000);
        let mut sources = Vec::new();
        let mut repairs = Vec::new();
        for frame in &frames {
            let (source, mut generated) = encoder.push(frame).unwrap();
            sources.push(source);
            repairs.append(&mut generated);
        }
        let mut decoder = WindowDecoder::new();
        let first = decoder.source(sources[0].esi, &sources[0].frame).unwrap();
        assert_eq!(first.frames.len(), 1);
        assert_eq!(first.frames[0].frame, frames[0]);
        assert_eq!(first.frames[0].origin, DeliveryOrigin::Source);
        let third = decoder.source(sources[2].esi, &sources[2].frame).unwrap();
        assert_eq!(third.frames.len(), 1);
        assert_eq!(third.frames[0].frame, frames[2]);
        assert_eq!(third.frames[0].origin, DeliveryOrigin::Source);
        let recovered = decoder
            .repair(
                repairs[2].rid,
                repairs[2].first_esi,
                repairs[2].symbol_count,
                &repairs[2].vector,
            )
            .unwrap();
        assert!(
            recovered
                .frames
                .iter()
                .any(|frame| frame.frame == frames[1] && frame.origin == DeliveryOrigin::Recovered)
        );
        let recovered_frame = recovered
            .frames
            .iter()
            .find(|frame| frame.origin == DeliveryOrigin::Recovered)
            .expect("missing recovered frame");
        assert_eq!(recovered_frame.esi, sources[1].esi);
        assert!(
            decoder
                .source(sources[1].esi, &sources[1].frame)
                .unwrap()
                .frames
                .is_empty()
        );
    }

    #[test]
    fn repair_first_recovery_normalizes_singleton_coefficient() {
        let frames = [frame(1), frame(2), frame(3)];
        let mut encoder = WindowEncoder::new(1_000);
        let generated = frames
            .iter()
            .map(|item| encoder.push(item).unwrap())
            .collect::<Vec<_>>();
        let repair = &generated[2].1[0];
        let mut decoder = WindowDecoder::new();

        assert!(
            decoder
                .repair(
                    repair.rid,
                    repair.first_esi,
                    repair.symbol_count,
                    &repair.vector,
                )
                .unwrap()
                .frames
                .is_empty()
        );
        decoder
            .source(generated[0].0.esi, &generated[0].0.frame)
            .unwrap();
        let delivery = decoder
            .source(generated[2].0.esi, &generated[2].0.frame)
            .unwrap();
        let recovered = delivery
            .frames
            .iter()
            .find(|item| item.origin == DeliveryOrigin::Recovered)
            .expect("repair-first row did not recover the missing source");
        assert_eq!(recovered.esi, generated[1].0.esi);
        assert_eq!(recovered.frame, frames[1]);
    }

    #[test]
    fn invalid_recovery_does_not_poison_source_slot() {
        let mut decoder = WindowDecoder::new();
        let discarded = decoder.repair(1, 0, 1, &[0, 0]).unwrap();
        assert!(discarded.discarded);
        assert!(decoder.rows.is_empty());

        let source = decoder.source(0, &frame(9)).unwrap();
        assert_eq!(source.frames.len(), 1);
        assert_eq!(source.frames[0].esi, 0);
        assert_eq!(source.frames[0].origin, DeliveryOrigin::Source);
    }

    #[test]
    fn repair_recovers_multiple_missing_sources_without_duplicate_delivery() {
        let frames = (0..12).map(|index| frame(index as u8)).collect::<Vec<_>>();
        let mut encoder = WindowEncoder::new(1_000);
        let mut generated = Vec::new();
        for frame in &frames {
            generated.push(encoder.push(frame).unwrap());
        }

        let mut decoder = WindowDecoder::new();
        let mut recovered = Vec::new();
        for (index, (source, repairs)) in generated.iter().enumerate() {
            if !matches!(index, 1 | 3) {
                decoder.source(source.esi, &source.frame).unwrap();
            }
            for repair in repairs {
                recovered.extend(
                    decoder
                        .repair(
                            repair.rid,
                            repair.first_esi,
                            repair.symbol_count,
                            &repair.vector,
                        )
                        .unwrap()
                        .frames
                        .into_iter()
                        .filter(|frame| frame.origin == DeliveryOrigin::Recovered),
                );
            }
        }

        recovered.sort_by_key(|frame| frame.esi);
        assert_eq!(
            recovered.iter().map(|frame| frame.esi).collect::<Vec<_>>(),
            vec![1, 3]
        );
        assert_eq!(recovered[0].frame, frames[1]);
        assert_eq!(recovered[1].frame, frames[3]);
    }

    #[test]
    fn invalid_repairs_are_rejected_before_allocation() {
        let mut decoder = WindowDecoder::new();
        assert_eq!(
            decoder.repair(1, 0, 0, &[1]),
            Err(FecError::InvalidRepairCount)
        );
        assert_eq!(
            decoder.repair(1, 0, 257, &[1]),
            Err(FecError::InvalidRepairCount)
        );
        assert_eq!(
            decoder.repair(1, 0, u16::MAX, &[1]),
            Err(FecError::InvalidRepairCount)
        );
        assert_eq!(
            decoder.repair(1, 0, 1, &[]),
            Err(FecError::RepairVectorTooLarge)
        );
        assert_eq!(
            decoder.repair(1, 0, 1, &vec![0; MAX_SYMBOL_BYTES + 1]),
            Err(FecError::RepairVectorTooLarge)
        );
    }

    #[test]
    fn reports_are_monotonic_and_bound_loss() {
        let mut estimator = LossEstimator::default();
        for sequence in 0..260 {
            estimator.observe(sequence * 2);
        }
        let report = estimator.take_report().unwrap();
        assert!(report.loss_ppm > 0);
        assert!(report.burst_milli >= 1_000);
        estimator.requeue_report(report);
        assert_eq!(estimator.take_report().unwrap().report_id, report.report_id);
    }

    #[test]
    fn unusable_reports_do_not_propose_more_repair() {
        let report = FecReport {
            report_id: 1,
            samples: 128,
            loss_ppm: 1_000_000,
            burst_milli: 1_000,
        };
        assert_eq!(window_rate_milli(WINDOW_CAPACITY, report, 8_000), None);
        assert_eq!(
            window_rate_milli(
                WINDOW_CAPACITY,
                FecReport {
                    samples: 127,
                    ..report
                },
                8_000,
            ),
            None
        );
        assert_eq!(
            window_rate_milli(
                WINDOW_CAPACITY,
                FecReport {
                    loss_ppm: 0,
                    ..report
                },
                8_000,
            ),
            Some(0)
        );
    }

    #[test]
    fn recovery_probe_is_a_bounded_reserved_frame() {
        let probe = recovery_probe_frame();
        assert_eq!(probe.len(), crate::crypto::FRAME_OVERHEAD);
        assert!(is_recovery_probe(&probe));
        assert!(!is_recovery_probe(&probe[1..]));
    }

    #[test]
    fn rate_updates_are_slew_limited() {
        assert_eq!(slew_rate_milli(1_000, 5_000, 8_000), 2_000);
        assert_eq!(slew_rate_milli(8_000, 0, 8_000), 7_500);
        assert_eq!(slew_rate_milli(8_000, 8_000, 4_000), 4_000);
    }

    #[test]
    fn startup_rebase_marks_the_lower_sequence_before_deciding() {
        let mut estimator = LossEstimator::default();
        estimator.observe(100);
        estimator.observe(90);
        assert_eq!(estimator.decided, 3);
        assert_eq!(estimator.lost, 2);
    }

    #[test]
    fn reorder_within_tolerance_is_not_loss() {
        let mut estimator = LossEstimator::default();
        for sequence in [0, 2, 1, 4, 3, 6, 5, 8, 7, 9, 10, 11, 12, 13, 14, 15] {
            estimator.observe(sequence);
        }
        assert_eq!(estimator.reordered(), 0);
        assert_eq!(estimator.take_report(), None);
    }

    #[test]
    fn late_packets_do_not_rewrite_decided_loss() {
        let mut estimator = LossEstimator::default();
        estimator.observe(0);
        for sequence in 2..=20 {
            estimator.observe(sequence);
        }
        let before = estimator.decided();
        estimator.observe(1);
        assert_eq!(estimator.decided(), before);
        assert_eq!(estimator.reordered(), 1);
    }

    #[test]
    fn decoder_publishes_duplicates_once_and_discards_expired_sources() {
        let mut encoder = WindowEncoder::new(1_000);
        let (source_a, _) = encoder.push(&frame(1)).unwrap();
        let (source_b, _) = encoder.push(&frame(2)).unwrap();
        let mut decoder = WindowDecoder::new();
        assert_eq!(decoder.width(), DECODER_WIDTH);
        let first = decoder.source(source_a.esi, &source_a.frame).unwrap();
        assert_eq!(first.frames.len(), 1);
        assert!(
            decoder
                .source(source_a.esi, &source_a.frame)
                .unwrap()
                .frames
                .is_empty()
        );

        for esi in 2..=513 {
            let delivery = decoder.source(esi, &frame((esi % 251) as u8)).unwrap();
            if esi == 513 {
                assert_eq!(delivery.lost, vec![source_b.esi]);
            }
        }
        let late = decoder.source(source_b.esi, &source_b.frame).unwrap();
        assert!(late.discarded);
        assert!(late.frames.is_empty());
        assert_eq!(late.lost, Vec::<u32>::new());
    }

    #[test]
    fn decoder_rebases_large_jumps_and_handles_esi_wrap() {
        let mut decoder = WindowDecoder::new();
        decoder.source(0, &frame(1)).unwrap();
        let jumped = decoder
            .source((MAX_REPAIR_WINDOW * 4 + 1) as u32, &frame(2))
            .unwrap();
        assert_eq!(jumped.frames.len(), 1);
        assert!(!jumped.discarded);
        let continued = decoder
            .source((MAX_REPAIR_WINDOW * 4 + 2) as u32, &frame(3))
            .unwrap();
        assert_eq!(continued.frames.len(), 1);

        let mut wrapped = WindowDecoder::new();
        for (esi, value) in [(u32::MAX - 1, 1), (u32::MAX, 2), (0, 3), (1, 4)] {
            let delivery = wrapped.source(esi, &frame(value)).unwrap();
            assert_eq!(delivery.frames.len(), 1);
            assert!(!delivery.discarded);
        }
    }

    #[test]
    fn feedback_outbox_keeps_only_the_newest_report() {
        let mut estimator = LossEstimator::default();
        estimator.requeue_report(FecReport {
            report_id: 3,
            samples: 128,
            loss_ppm: 10_000,
            burst_milli: 1_000,
        });
        estimator.requeue_report(FecReport {
            report_id: 4,
            samples: 128,
            loss_ppm: 20_000,
            burst_milli: 1_000,
        });
        estimator.requeue_report(FecReport {
            report_id: 2,
            samples: 128,
            loss_ppm: 1_000,
            burst_milli: 1_000,
        });
        assert_eq!(estimator.take_report().unwrap().report_id, 4);
    }

    #[test]
    fn direct_and_recovered_frames_are_distinguishable() {
        let frame_a = frame(1);
        let frame_b = frame(2);
        let mut encoder = WindowEncoder::new(1_000);
        let (source_a, mut repairs_a) = encoder.push(&frame_a).unwrap();
        let (_source_b, repairs_b) = encoder.push(&frame_b).unwrap();
        repairs_a.extend(repairs_b);
        let mut decoder = WindowDecoder::new();
        let direct = decoder.source(source_a.esi, &source_a.frame).unwrap();
        assert_eq!(direct.frames[0].origin, DeliveryOrigin::Source);
        let recovered = decoder
            .repair(
                repairs_a[1].rid,
                repairs_a[1].first_esi,
                repairs_a[1].symbol_count,
                &repairs_a[1].vector,
            )
            .unwrap();
        assert!(recovered.frames.iter().all(|frame| {
            frame.origin == DeliveryOrigin::Recovered && frame.esi == 1 && frame.frame == frame_b
        }));
    }

    #[test]
    fn decoder_clone_shares_source_slot_vectors() {
        let mut decoder = WindowDecoder::new();
        decoder.source(0, &frame(1)).unwrap();
        let cloned = decoder.clone();
        let index = decoder.index(0);
        assert!(Arc::ptr_eq(
            &decoder.slots[index].vector,
            &cloned.slots[index].vector
        ));
    }

    #[test]
    fn encoder_rate_and_admission_helpers_cover_zero_credit_and_boundaries() {
        let mut encoder = WindowEncoder::new(MAX_RATE_MILLI + 1);
        assert_eq!(encoder.rate_milli(), MAX_RATE_MILLI);
        encoder.restore_tail_repairs(1);
        assert!(encoder.credit_milli_for_test() > 0);
        encoder.set_rate_milli(0);
        assert_eq!(encoder.rate_milli(), 0);
        assert_eq!(encoder.credit_milli_for_test(), 0);
        assert!(!encoder.has_pending_tail() || encoder.flush_tail().is_empty());
        encoder.restore_tail_repairs(0);
        encoder.finish_tail();
    }

    #[test]
    fn decoder_rejects_stale_repairs_and_reports_window_admission_edges() {
        let mut decoder = WindowDecoder::new();
        assert!(decoder.repair_window_admissible(0, 1).unwrap());
        assert_eq!(
            decoder.repair_window_admissible(0, 0),
            Err(FecError::InvalidRepairCount)
        );

        decoder.source(10_000, &frame(1)).unwrap();
        let encoded = encode_repair(1, std::iter::once(&symbol(&frame(2)).unwrap()));
        let stale = decoder.repair(1, 0, 1, &encoded).unwrap();
        assert!(stale.discarded);
        assert!(!decoder.repair_window_admissible(0, 1).unwrap());
        assert!(decoder.repair_window_admissible(10_000, 1).unwrap());
    }

    #[test]
    fn decoder_substitution_and_reset_paths_discard_invalid_or_duplicate_rows() {
        let mut decoder = WindowDecoder::new();
        let mut invalid = Delivery::default();
        decoder.substitute(
            0,
            Arc::new(vec![0, 1, 2]),
            DeliveryOrigin::Recovered,
            &mut invalid,
        );
        assert!(invalid.discarded);

        let vector = Arc::new(symbol(&frame(7)).unwrap());
        let mut first = Delivery::default();
        decoder.substitute(0, vector.clone(), DeliveryOrigin::Source, &mut first);
        assert_eq!(first.frames.len(), 1);
        let mut duplicate = Delivery::default();
        decoder.substitute(0, vector, DeliveryOrigin::Recovered, &mut duplicate);
        assert!(duplicate.frames.is_empty());

        decoder.source(1, &frame(8)).unwrap();
        let unknown_index = decoder.index(1);
        decoder.slots[unknown_index].known = false;
        let mut reset = Delivery::default();
        decoder.reset_window((MAX_REPAIR_WINDOW * 8 + 10) as u32, &mut reset);
        assert_eq!(reset.lost, vec![1]);
        let mut held = vec![1, 2, 3];
        ensure_len(&mut held, 8);
        assert_eq!(held.len(), 8);
        assert_eq!(leading(&[0; 4], 0, 4), None);
    }

    #[test]
    fn loss_and_rate_math_cover_rebase_report_and_probability_edges() {
        let mut estimator = LossEstimator::default();
        estimator.make_report();
        assert!(estimator.latest_report().is_none());
        estimator.observe(0);
        estimator.observe(MAX_DECIDED_PER_ARRIVAL + 1);
        assert_eq!(estimator.decided(), 0);

        assert_eq!(binomial_tail_below(0, 0.5, 0), 0.0);
        assert_eq!(binomial_tail_below(2, 0.5, 3), 1.0);
        assert_eq!(binomial_tail_below(2, 0.0, 1), 1.0);
        assert_eq!(binomial_tail_below(2, 1.0, 1), 0.0);
        assert_eq!(
            window_rate_milli(
                0,
                FecReport {
                    report_id: 1,
                    samples: 128,
                    loss_ppm: 1,
                    burst_milli: 1000
                },
                1000
            ),
            None
        );
        assert_eq!(
            window_rate_milli(
                WINDOW_CAPACITY,
                FecReport {
                    report_id: 1,
                    samples: 128,
                    loss_ppm: 999_000,
                    burst_milli: 1000
                },
                0
            ),
            Some(0)
        );
    }

    #[test]
    fn repair_window_admission_tolerates_large_forward_jumps() {
        let mut decoder = WindowDecoder::new();
        decoder.source(0, &frame(1)).unwrap();
        // A repair far ahead of the current window is admitted without
        // computing a lower bound.
        assert!(decoder.repair_window_admissible(2_000, 1).unwrap());
        // A moderate forward advance computes a fresh window lower bound.
        assert!(decoder.repair_window_admissible(1_000, 1).unwrap());
    }

    #[test]
    fn decoder_row_elimination_merges_overlapping_repair_rows() {
        let mut decoder = WindowDecoder::new();
        decoder.source(0, &frame(1)).unwrap();
        let mut first = Delivery::default();
        let mut coefficients = vec![0u8; DECODER_WIDTH];
        coefficients[decoder.index(1)] = coefficient(7, 0);
        coefficients[decoder.index(2)] = coefficient(7, 1);
        decoder.insert_row(coefficients, symbol(&frame(2)).unwrap(), &mut first);
        assert!(first.frames.is_empty());
        assert_eq!(decoder.rows.len(), 1);

        // A second row that shares the existing row's pivot eliminates in
        // both directions: the new row is reduced against the existing row
        // and the existing row is reduced against the new row.
        let mut second = Delivery::default();
        let mut coefficients = vec![0u8; DECODER_WIDTH];
        coefficients[decoder.index(1)] = 1;
        coefficients[decoder.index(200)] = 7;
        decoder.insert_row(coefficients, symbol(&frame(3)).unwrap(), &mut second);
        assert!(second.frames.is_empty());
        assert_eq!(decoder.rows.len(), 2);
        assert!(
            decoder
                .rows
                .iter()
                .all(|row| row.coefficients[decoder.index(row.pivot)] != 0)
        );
    }

    #[test]
    fn decoder_drops_rows_that_reference_evicted_unknown_symbols() {
        let mut decoder = WindowDecoder::new();
        decoder.source(0, &frame(1)).unwrap();
        let mut out = Delivery::default();
        let mut coefficients = vec![0u8; DECODER_WIDTH];
        coefficients[decoder.index(1)] = coefficient(9, 0);
        coefficients[decoder.index(2)] = coefficient(9, 1);
        decoder.insert_row(coefficients, symbol(&frame(2)).unwrap(), &mut out);
        assert_eq!(decoder.rows.len(), 1);
        // Advancing the window evicts esi 1 while it is still unknown; the
        // row that referenced it is no longer a valid equation and is
        // dropped instead of surviving into the new window.
        decoder.source(513, &frame(3)).unwrap();
        assert!(decoder.rows.is_empty());
    }

    #[test]
    fn decoder_rows_are_capped_at_decoder_width() {
        let mut decoder = WindowDecoder::new();
        decoder.source(0, &frame(1)).unwrap();
        // Fill the row table to capacity with single-coefficient rows at
        // distinct indices. They sit below the window so `leading` still
        // finds them, and harvest only runs inside insert_row.
        for index in 0..DECODER_WIDTH {
            let mut coefficients = vec![0u8; DECODER_WIDTH];
            coefficients[index] = 2;
            decoder.rows.push(Equation {
                pivot: index as u32,
                coefficients: Arc::new(coefficients),
                vector: Arc::new(vec![0, 0]),
            });
        }
        assert_eq!(decoder.rows.len(), DECODER_WIDTH);
        // The next repair reduces against the existing rows and still lands
        // in the table, so the oldest row is evicted before the new one is
        // stored and the width cap is preserved.
        let mut out = Delivery::default();
        let mut coefficients = vec![0u8; DECODER_WIDTH];
        coefficients[392] = 3;
        coefficients[500] = 5;
        decoder.insert_row(coefficients, vec![0, 0], &mut out);
        // The two-symbol row survives elimination (rows.len() was 512 at the
        // cap check), while every pre-existing singleton row is harvested
        // and discarded because its vector is not a decodable symbol.
        assert_eq!(decoder.rows.len(), 1);
        assert!(out.discarded);
        assert!(out.frames.is_empty());
    }

    #[test]
    fn loss_estimator_decides_ring_sized_gaps() {
        let mut estimator = LossEstimator::default();
        estimator.observe(0);
        estimator.observe(2000);
        assert_eq!(estimator.decided(), 1993);
        assert_eq!(estimator.reordered(), 0);
    }

    #[test]
    fn window_rate_milli_binary_searches_a_usable_rate() {
        let report = FecReport {
            report_id: 1,
            samples: 128,
            loss_ppm: 10_000,
            burst_milli: 1_000,
        };
        let rate = window_rate_milli(WINDOW_CAPACITY, report, 8_000).unwrap();
        assert!((1..=8_000).contains(&rate));
        // A lower configured cap bounds the proposed rate.
        let capped = window_rate_milli(WINDOW_CAPACITY, report, 2_000).unwrap();
        assert!(capped <= 2_000);
    }
}
