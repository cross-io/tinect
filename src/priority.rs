//! RFC-0017 local admission policy.
//!
//! This module deliberately decides only local queue admission. It has no
//! socket or QUIC dependency, so callers cannot accidentally claim ordering
//! of asynchronous carrier writes as a protocol guarantee.

use std::{
    collections::VecDeque,
    sync::{Mutex, MutexGuard},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PriorityClass {
    S0,
    S1,
    D0,
    D1,
    D2,
}

const MAX_CONSECUTIVE_S0: u8 = 8;
const MAX_CONSECUTIVE_STREAM: u8 = 8;

#[derive(Debug, Default)]
pub struct Admission {
    pending: [VecDeque<Pending>; 5],
    next_ticket: u64,
    consecutive_s0: u8,
    consecutive_stream: u8,
}

#[derive(Debug, Clone, Copy)]
struct Pending {
    ticket: u64,
    bytes: usize,
}

const MAX_S0_PENDING: usize = 256;
const MAX_S1_PENDING: usize = 4096;
const MAX_S0_PENDING_BYTES: usize = 1024 * 1024;
const MAX_S1_PENDING_BYTES: usize = 4 * 1024 * 1024;

#[derive(Debug, Default)]
struct GateState {
    admission: Admission,
    granted: [VecDeque<u64>; 5],
}

/// Concurrent, local-only RFC-0017 admission gate. A granted permit means a
/// message may enter its writer/carrier path; it is never held across I/O.
#[derive(Debug, Default)]
pub struct Gate {
    state: Mutex<GateState>,
    wake: tokio::sync::Notify,
}

struct QueuedStream<'a> {
    gate: &'a Gate,
    class: PriorityClass,
    ticket: Option<u64>,
}

impl QueuedStream<'_> {
    fn disarm(&mut self) {
        self.ticket = None;
    }
}

impl Drop for QueuedStream<'_> {
    fn drop(&mut self) {
        let Some(ticket) = self.ticket.take() else {
            return;
        };
        let mut state = self.gate.lock_state();
        let index = Admission::index(self.class);
        state.admission.cancel(self.class, ticket);
        if let Some(position) = state.granted[index]
            .iter()
            .position(|granted| *granted == ticket)
        {
            state.granted[index].remove(position);
        }
        Gate::pump(&mut state);
        drop(state);
        self.gate.wake.notify_waiters();
    }
}

impl Gate {
    fn lock_state(&self) -> MutexGuard<'_, GateState> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn stream_limits(class: PriorityClass) -> Option<(usize, usize)> {
        match class {
            PriorityClass::S0 => Some((MAX_S0_PENDING, MAX_S0_PENDING_BYTES)),
            PriorityClass::S1 => Some((MAX_S1_PENDING, MAX_S1_PENDING_BYTES)),
            PriorityClass::D0 | PriorityClass::D1 | PriorityClass::D2 => None,
        }
    }

    fn pump(state: &mut GateState) {
        if let Some((class, ticket)) = state.admission.admit_next_entry() {
            let slot = &mut state.granted[Admission::index(class)];
            slot.push_back(ticket);
        }
    }

    fn take_grant(state: &mut GateState, class: PriorityClass, ticket: u64) -> bool {
        let slot = &mut state.granted[Admission::index(class)];
        let Some(position) = slot.iter().position(|granted| *granted == ticket) else {
            return false;
        };
        slot.remove(position);
        true
    }

    /// Wait for a stream writer admission. Its bounded pending count is part
    /// of the observable local failure boundary, not a carrier flow-control
    /// limit.
    pub async fn admit_stream(&self, class: PriorityClass, bytes: usize) -> bool {
        debug_assert!(matches!(class, PriorityClass::S0 | PriorityClass::S1));
        let mut queued = QueuedStream {
            gate: self,
            class,
            ticket: None,
        };
        loop {
            let notified = self.wake.notified();
            // Register before inspecting the queue. `notify_waiters` does
            // not retain a notification when no waiter is registered; doing
            // this first closes the wake-up race between the state check and
            // awaiting the next admission grant.
            tokio::pin!(notified);
            notified.as_mut().enable();
            {
                let mut state = self.lock_state();
                if queued.ticket.is_none() {
                    let current = state.admission.pending(class);
                    if Self::stream_limits(class).is_some_and(|(count, byte_limit)| {
                        current >= count
                            || bytes
                                > byte_limit.saturating_sub(state.admission.pending_bytes(class))
                    }) {
                        return false;
                    }
                    queued.ticket = Some(state.admission.enqueue(class, bytes));
                }
                Self::pump(&mut state);
                if Self::take_grant(
                    &mut state,
                    class,
                    queued.ticket.expect("queued stream has a ticket"),
                ) {
                    queued.disarm();
                    drop(state);
                    self.wake.notify_waiters();
                    return true;
                }
            }
            notified.await;
        }
    }

    /// Datagram admission is deliberately non-blocking. A rejected D2 caller
    /// can drop immediately; a later attempt participates in the same fair
    /// arbitration with currently waiting stream work.
    pub fn try_admit_datagram(&self, class: PriorityClass) -> bool {
        debug_assert!(matches!(
            class,
            PriorityClass::D0 | PriorityClass::D1 | PriorityClass::D2
        ));
        let Ok(mut state) = self.state.try_lock() else {
            return false;
        };
        let ticket = state.admission.enqueue(class, 0);
        Self::pump(&mut state);
        let admitted = Self::take_grant(&mut state, class, ticket);
        if !admitted {
            state.admission.cancel(class, ticket);
        }
        drop(state);
        self.wake.notify_waiters();
        admitted
    }
}

impl Admission {
    const fn index(class: PriorityClass) -> usize {
        match class {
            PriorityClass::S0 => 0,
            PriorityClass::S1 => 1,
            PriorityClass::D0 => 2,
            PriorityClass::D1 => 3,
            PriorityClass::D2 => 4,
        }
    }

    pub fn enqueue(&mut self, class: PriorityClass, bytes: usize) -> u64 {
        self.next_ticket = self.next_ticket.wrapping_add(1).max(1);
        let ticket = self.next_ticket;
        self.pending[Self::index(class)].push_back(Pending { ticket, bytes });
        ticket
    }

    pub fn cancel(&mut self, class: PriorityClass, ticket: u64) -> bool {
        let pending = &mut self.pending[Self::index(class)];
        let Some(position) = pending.iter().position(|entry| entry.ticket == ticket) else {
            return false;
        };
        pending.remove(position);
        true
    }

    pub fn pending(&self, class: PriorityClass) -> usize {
        self.pending[Self::index(class)].len()
    }

    pub fn pending_bytes(&self, class: PriorityClass) -> usize {
        self.pending[Self::index(class)]
            .iter()
            .map(|entry| entry.bytes)
            .sum()
    }

    /// Select and consume one local admission. This is intentionally a queue
    /// decision, not a permit held across a carrier await.
    pub fn admit_next(&mut self) -> Option<PriorityClass> {
        self.admit_next_entry().map(|(class, _)| class)
    }

    fn admit_next_entry(&mut self) -> Option<(PriorityClass, u64)> {
        let stream_waiting = self.pending(PriorityClass::S0) + self.pending(PriorityClass::S1);
        let datagram = [PriorityClass::D0, PriorityClass::D1, PriorityClass::D2]
            .into_iter()
            .find(|class| self.pending(*class) > 0);

        let selected = if stream_waiting > 0
            && !(datagram.is_some() && self.consecutive_stream >= MAX_CONSECUTIVE_STREAM)
        {
            if self.pending(PriorityClass::S0) > 0
                && !(self.pending(PriorityClass::S1) > 0
                    && self.consecutive_s0 >= MAX_CONSECUTIVE_S0)
            {
                PriorityClass::S0
            } else {
                PriorityClass::S1
            }
        } else {
            datagram?
        };

        let pending = self.pending[Self::index(selected)]
            .pop_front()
            .expect("selected class has a pending entry");
        match selected {
            PriorityClass::S0 => {
                self.consecutive_s0 = self.consecutive_s0.saturating_add(1);
                self.consecutive_stream = self.consecutive_stream.saturating_add(1);
            }
            PriorityClass::S1 => {
                self.consecutive_s0 = 0;
                self.consecutive_stream = self.consecutive_stream.saturating_add(1);
            }
            PriorityClass::D0 | PriorityClass::D1 | PriorityClass::D2 => {
                self.consecutive_s0 = 0;
                self.consecutive_stream = 0;
            }
        }
        Some((selected, pending.ticket))
    }
}

#[cfg_attr(coverage_nightly, coverage(off))]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn s0_yields_to_s1_after_eight_admissions() {
        let mut admission = Admission::default();
        for _ in 0..9 {
            admission.enqueue(PriorityClass::S0, 0);
        }
        admission.enqueue(PriorityClass::S1, 0);
        for _ in 0..8 {
            assert_eq!(admission.admit_next(), Some(PriorityClass::S0));
        }
        assert_eq!(admission.admit_next(), Some(PriorityClass::S1));
    }

    #[test]
    fn streams_yield_to_datagram_after_eight_admissions() {
        let mut admission = Admission::default();
        for _ in 0..9 {
            admission.enqueue(PriorityClass::S0, 0);
        }
        admission.enqueue(PriorityClass::D2, 0);
        for _ in 0..8 {
            assert_eq!(admission.admit_next(), Some(PriorityClass::S0));
        }
        assert_eq!(admission.admit_next(), Some(PriorityClass::D2));
    }

    #[test]
    fn datagram_classes_are_ordered() {
        let mut admission = Admission::default();
        admission.enqueue(PriorityClass::D2, 0);
        admission.enqueue(PriorityClass::D1, 0);
        admission.enqueue(PriorityClass::D0, 0);
        assert_eq!(admission.admit_next(), Some(PriorityClass::D0));
        assert_eq!(admission.admit_next(), Some(PriorityClass::D1));
        assert_eq!(admission.admit_next(), Some(PriorityClass::D2));
    }

    #[tokio::test]
    async fn stream_byte_budget_rejects_before_admission() {
        let gate = Gate::default();
        {
            let mut state = gate.state.lock().unwrap();
            state
                .admission
                .enqueue(PriorityClass::S1, MAX_S1_PENDING_BYTES);
        }
        assert!(!gate.admit_stream(PriorityClass::S1, 1).await);
    }

    #[tokio::test]
    async fn cancelled_stream_waiter_releases_its_exact_queue_budget() {
        let gate = std::sync::Arc::new(Gate::default());
        gate.state
            .lock()
            .unwrap()
            .admission
            .enqueue(PriorityClass::S0, 1);
        let waiter_gate = gate.clone();
        let waiter =
            tokio::spawn(async move { waiter_gate.admit_stream(PriorityClass::S1, 123).await });
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            loop {
                if gate
                    .state
                    .lock()
                    .unwrap()
                    .admission
                    .pending(PriorityClass::S1)
                    == 1
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        waiter.abort();
        assert!(waiter.await.unwrap_err().is_cancelled());

        let state = gate.state.lock().unwrap();
        assert_eq!(state.admission.pending(PriorityClass::S1), 0);
        assert_eq!(state.admission.pending_bytes(PriorityClass::S1), 0);
        assert!(state.granted[Admission::index(PriorityClass::S1)].is_empty());
    }

    #[test]
    fn dropping_a_granted_stream_removes_only_its_ticket() {
        let gate = Gate::default();
        let ticket = {
            let mut state = gate.state.lock().unwrap();
            let ticket = state.admission.enqueue(PriorityClass::S0, 7);
            state.granted[Admission::index(PriorityClass::S0)].push_back(ticket);
            ticket
        };
        assert_eq!(Gate::stream_limits(PriorityClass::D0), None);
        drop(QueuedStream {
            gate: &gate,
            class: PriorityClass::S0,
            ticket: Some(ticket),
        });
        let state = gate.state.lock().unwrap();
        assert_eq!(state.admission.pending(PriorityClass::S0), 0);
        assert!(state.granted[Admission::index(PriorityClass::S0)].is_empty());
    }
}
