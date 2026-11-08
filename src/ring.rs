use crate::error::StorageError;
use bytes::Bytes;
use std::collections::VecDeque;
use std::sync::RwLock;

/// A chunk of media stored in the circular ring buffer.
#[derive(Debug, Clone)]
pub struct RingChunk {
    /// Monotonically increasing chunk sequence number.
    pub sequence: u64,
    /// Monotonically increasing stream byte offset at the start of this chunk.
    pub byte_offset: u64,
    /// The immutable zero-copy byte payload.
    pub data: Bytes,
    /// Indicates if this chunk begins on an IDR / Keyframe boundary.
    pub is_keyframe: bool,
}

/// Statistics and metrics for the in-memory ring buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RingStats {
    pub total_bytes: usize,
    pub max_capacity_bytes: usize,
    pub chunk_count: usize,
    pub oldest_sequence: Option<u64>,
    pub newest_sequence: Option<u64>,
    pub total_bytes_written: u64,
}

/// A high-throughput, thread-safe circular buffer for live stream jitter shielding and timeshift.
pub struct LiveRingBuffer {
    max_capacity_bytes: usize,
    state: RwLock<RingState>,
}

struct RingState {
    chunks: VecDeque<RingChunk>,
    current_bytes: usize,
    next_sequence: u64,
    next_byte_offset: u64,
    total_bytes_written: u64,
    latest_keyframe_seq: Option<u64>,
}

impl LiveRingBuffer {
    /// Create a new ring buffer with the specified maximum byte capacity.
    pub fn new(max_capacity_bytes: usize) -> Self {
        Self {
            max_capacity_bytes,
            state: RwLock::new(RingState {
                chunks: VecDeque::new(),
                current_bytes: 0,
                next_sequence: 0,
                next_byte_offset: 0,
                total_bytes_written: 0,
                latest_keyframe_seq: None,
            }),
        }
    }

    /// Push a chunk of bytes into the ring buffer.
    /// Automatically evicts older chunks when capacity is reached.
    pub fn push(&self, data: Bytes, is_keyframe: bool) -> Result<u64, StorageError> {
        let chunk_len = data.len();
        let mut state = self
            .state
            .write()
            .map_err(|_| StorageError::Io(std::io::Error::other("Ring buffer lock poisoned")))?;

        let seq = state.next_sequence;
        let byte_offset = state.next_byte_offset;

        state.next_sequence += 1;
        state.next_byte_offset += chunk_len as u64;
        state.total_bytes_written += chunk_len as u64;
        state.current_bytes += chunk_len;

        if is_keyframe {
            state.latest_keyframe_seq = Some(seq);
        }

        state.chunks.push_back(RingChunk {
            sequence: seq,
            byte_offset,
            data,
            is_keyframe,
        });

        // Evict oldest chunks while exceeding capacity
        while state.current_bytes > self.max_capacity_bytes && state.chunks.len() > 1 {
            if let Some(removed) = state.chunks.pop_front() {
                state.current_bytes = state.current_bytes.saturating_sub(removed.data.len());
            }
        }

        Ok(seq)
    }

    /// Read chunks starting from `from_sequence` up to `max_chunks`.
    /// Returns the chunks and the next sequence number to read from.
    pub fn read_from(
        &self,
        from_sequence: u64,
        max_chunks: usize,
    ) -> Result<(Vec<RingChunk>, u64), StorageError> {
        let state = self
            .state
            .read()
            .map_err(|_| StorageError::Io(std::io::Error::other("Ring buffer lock poisoned")))?;

        if state.chunks.is_empty() {
            return Ok((Vec::new(), from_sequence));
        }

        let oldest_seq = state.chunks.front().map(|c| c.sequence).unwrap_or(0);
        let newest_seq = state.chunks.back().map(|c| c.sequence).unwrap_or(0);

        if from_sequence < oldest_seq {
            return Err(StorageError::RingUnderflow {
                requested: from_sequence,
                oldest: oldest_seq,
            });
        }

        if from_sequence > newest_seq {
            // Reader is ahead of or caught up to the write head
            return Ok((Vec::new(), from_sequence));
        }

        let start_index = (from_sequence - oldest_seq) as usize;
        let mut results = Vec::with_capacity(max_chunks.min(state.chunks.len() - start_index));

        for chunk in state.chunks.iter().skip(start_index).take(max_chunks) {
            results.push(chunk.clone());
        }

        let next_seq = results
            .last()
            .map(|c| c.sequence + 1)
            .unwrap_or(from_sequence);

        Ok((results, next_seq))
    }

    /// Return the sequence of the most recent keyframe, if available.
    pub fn latest_keyframe_sequence(&self) -> Result<Option<u64>, StorageError> {
        let state = self
            .state
            .read()
            .map_err(|_| StorageError::Io(std::io::Error::other("Ring buffer lock poisoned")))?;

        // Verify the keyframe is still in the buffer
        if let Some(key_seq) = state.latest_keyframe_seq
            && let Some(oldest) = state.chunks.front()
            && key_seq >= oldest.sequence
        {
            return Ok(Some(key_seq));
        }

        Ok(None)
    }

    /// Return the oldest sequence number currently in the ring buffer.
    pub fn oldest_sequence(&self) -> Option<u64> {
        self.state.read().ok()?.chunks.front().map(|c| c.sequence)
    }

    /// Query current buffer metrics and telemetry.
    pub fn stats(&self) -> Result<RingStats, StorageError> {
        let state = self
            .state
            .read()
            .map_err(|_| StorageError::Io(std::io::Error::other("Ring buffer lock poisoned")))?;

        Ok(RingStats {
            total_bytes: state.current_bytes,
            max_capacity_bytes: self.max_capacity_bytes,
            chunk_count: state.chunks.len(),
            oldest_sequence: state.chunks.front().map(|c| c.sequence),
            newest_sequence: state.chunks.back().map(|c| c.sequence),
            total_bytes_written: state.total_bytes_written,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ring_push_and_read() {
        let ring = LiveRingBuffer::new(1024 * 1024);
        let data1 = Bytes::from_static(b"packet_1");
        let data2 = Bytes::from_static(b"packet_2");

        let s1 = ring.push(data1, true).expect("push 1");
        let s2 = ring.push(data2, false).expect("push 2");

        assert_eq!(s1, 0);
        assert_eq!(s2, 1);

        let (chunks, next_seq) = ring.read_from(0, 10).expect("read");
        assert_eq!(chunks.len(), 2);
        assert_eq!(chunks[0].data, Bytes::from_static(b"packet_1"));
        assert!(chunks[0].is_keyframe);
        assert_eq!(chunks[1].data, Bytes::from_static(b"packet_2"));
        assert!(!chunks[1].is_keyframe);
        assert_eq!(next_seq, 2);
    }

    #[test]
    fn test_ring_eviction_on_capacity() {
        // Small 20-byte ring
        let ring = LiveRingBuffer::new(20);
        let chunk1 = Bytes::from(vec![1u8; 10]);
        let chunk2 = Bytes::from(vec![2u8; 10]);
        let chunk3 = Bytes::from(vec![3u8; 10]);

        ring.push(chunk1, false).expect("push 1");
        ring.push(chunk2, false).expect("push 2");
        ring.push(chunk3, false).expect("push 3");

        let stats = ring.stats().expect("stats");
        assert!(stats.total_bytes <= 20);
        assert_eq!(stats.oldest_sequence, Some(1));
        assert_eq!(stats.newest_sequence, Some(2));

        // Reading sequence 0 should now underflow
        let err = ring.read_from(0, 5).unwrap_err();
        match err {
            StorageError::RingUnderflow { requested, oldest } => {
                assert_eq!(requested, 0);
                assert_eq!(oldest, 1);
            }
            _ => panic!("Expected RingUnderflow"),
        }
    }
}
