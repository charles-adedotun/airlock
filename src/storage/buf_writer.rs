use std::io::Result as IoResult;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncWrite, AsyncWriteExt};

/// Default capacity for coalescing network frames into disk blocks (512 KiB).
pub const DEFAULT_BUFFER_CAPACITY: usize = 512 * 1024;

/// High-performance asynchronous buffered chunk writer designed to shield
/// the Tokio runtime thread pool and disk controllers from micro-write thrashing.
pub struct AsyncBufferedChunkWriter<W> {
    inner: W,
    buf: Vec<u8>,
    capacity: usize,
    total_bytes_written: u64,
    flushes_count: u64,
    chunks_coalesced_count: u64,
}

impl<W> AsyncBufferedChunkWriter<W> {
    /// Creates a writer with the standard 512 KiB buffer capacity.
    pub fn new(inner: W) -> Self {
        Self::with_capacity(inner, DEFAULT_BUFFER_CAPACITY)
    }

    /// Creates a writer with a custom buffer capacity.
    pub fn with_capacity(inner: W, capacity: usize) -> Self {
        Self {
            inner,
            buf: Vec::with_capacity(capacity),
            capacity,
            total_bytes_written: 0,
            flushes_count: 0,
            chunks_coalesced_count: 0,
        }
    }

    /// Returns the number of unwritten bytes currently sitting in the buffer.
    pub fn bytes_buffered(&self) -> usize {
        self.buf.len()
    }

    /// Returns the total number of bytes successfully written to the underlying sink.
    pub fn total_bytes_written(&self) -> u64 {
        self.total_bytes_written
    }

    /// Total number of buffer flushes to the underlying sink.
    pub fn flushes_count(&self) -> u64 {
        self.flushes_count
    }

    /// Total number of chunks absorbed into the user-space buffer.
    pub fn chunks_coalesced_count(&self) -> u64 {
        self.chunks_coalesced_count
    }

    /// Reference to the underlying writer.
    pub fn get_ref(&self) -> &W {
        &self.inner
    }

    /// Mutable reference to the underlying writer.
    pub fn get_mut(&mut self) -> &mut W {
        &mut self.inner
    }

    /// Consumes the wrapper, returning the underlying writer.
    pub fn into_inner(self) -> W {
        self.inner
    }
}

impl<W: AsyncWrite + Unpin> AsyncBufferedChunkWriter<W> {
    /// Appends a network chunk to the buffer.
    /// If the chunk exceeds or fills the 512 KiB buffer, it is flushed to disk.
    pub async fn write_chunk(&mut self, chunk: &[u8]) -> IoResult<()> {
        self.chunks_coalesced_count += 1;

        // If chunk is larger than buffer capacity, flush existing buffer and write chunk directly
        if chunk.len() >= self.capacity {
            self.flush_buffer().await?;
            self.inner.write_all(chunk).await?;
            self.total_bytes_written += chunk.len() as u64;
            self.flushes_count += 1;
            return Ok(());
        }

        // If chunk overflows available capacity, flush first
        if self.buf.len() + chunk.len() > self.capacity {
            self.flush_buffer().await?;
        }

        self.buf.extend_from_slice(chunk);
        Ok(())
    }

    /// Flushes all buffered bytes to the underlying writer.
    pub async fn flush_buffer(&mut self) -> IoResult<()> {
        if !self.buf.is_empty() {
            let len = self.buf.len();
            self.inner.write_all(&self.buf).await?;
            self.total_bytes_written += len as u64;
            self.flushes_count += 1;
            self.buf.clear();
        }
        Ok(())
    }

    /// Flushes buffered bytes and syncs the underlying writer.
    pub async fn flush_all(&mut self) -> IoResult<()> {
        self.flush_buffer().await?;
        self.inner.flush().await
    }
}

impl<W: AsyncWrite + Unpin> AsyncWrite for AsyncBufferedChunkWriter<W> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<IoResult<usize>> {
        // If buffer is full, flush it out
        if self.buf.len() >= self.capacity {
            while !self.buf.is_empty() {
                let me = &mut *self;
                let n = match Pin::new(&mut me.inner).poll_write(cx, &me.buf)? {
                    Poll::Ready(n) => n,
                    Poll::Pending => return Poll::Pending,
                };
                if n == 0 {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::WriteZero,
                        "Underlying writer accepted 0 bytes",
                    )));
                }
                me.total_bytes_written += n as u64;
                me.buf.drain(..n);
            }
            self.flushes_count += 1;
        }

        let available = self.capacity - self.buf.len();
        let to_copy = std::cmp::min(available, buf.len());
        self.buf.extend_from_slice(&buf[..to_copy]);
        self.chunks_coalesced_count += 1;
        Poll::Ready(Ok(to_copy))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<IoResult<()>> {
        while !self.buf.is_empty() {
            let me = &mut *self;
            let n = match Pin::new(&mut me.inner).poll_write(cx, &me.buf)? {
                Poll::Ready(n) => n,
                Poll::Pending => return Poll::Pending,
            };
            if n == 0 {
                return Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::WriteZero,
                    "Flush accepted 0 bytes",
                )));
            }
            me.total_bytes_written += n as u64;
            me.buf.drain(..n);
        }
        self.flushes_count += 1;
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<IoResult<()>> {
        match self.as_mut().poll_flush(cx)? {
            Poll::Ready(()) => Pin::new(&mut self.inner).poll_shutdown(cx),
            Poll::Pending => Poll::Pending,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[tokio::test]
    async fn test_coalesces_small_chunks() {
        let sink = Cursor::new(Vec::new());
        let mut writer = AsyncBufferedChunkWriter::with_capacity(sink, 1024); // 1 KiB capacity

        // Write 10 chunks of 100 bytes = 1000 bytes (< 1024)
        for _ in 0..10 {
            writer.write_chunk(&[0x47; 100]).await.unwrap();
        }

        assert_eq!(writer.bytes_buffered(), 1000);
        assert_eq!(writer.total_bytes_written(), 0); // Not flushed to sink yet!
        assert_eq!(writer.flushes_count(), 0);

        // Next chunk of 100 bytes pushes total to 1100 > 1024.
        // It should flush the first 1000 bytes to sink and keep 100 in buffer.
        writer.write_chunk(&[0x47; 100]).await.unwrap();

        assert_eq!(writer.bytes_buffered(), 100);
        assert_eq!(writer.total_bytes_written(), 1000);
        assert_eq!(writer.flushes_count(), 1);

        // Final flush
        writer.flush_all().await.unwrap();
        assert_eq!(writer.bytes_buffered(), 0);
        assert_eq!(writer.total_bytes_written(), 1100);

        let sink = writer.into_inner();
        assert_eq!(sink.into_inner().len(), 1100);
    }

    #[tokio::test]
    async fn test_large_chunk_bypass() {
        let sink = Cursor::new(Vec::new());
        let mut writer = AsyncBufferedChunkWriter::with_capacity(sink, 1024);

        // Preload 200 bytes
        writer.write_chunk(&[0xAA; 200]).await.unwrap();
        assert_eq!(writer.bytes_buffered(), 200);

        // Write chunk of 2048 bytes (> capacity)
        let large_chunk = vec![0xBB; 2048];
        writer.write_chunk(&large_chunk).await.unwrap();

        // Should have flushed the 200 bytes, written the 2048 directly, and buffer is empty
        assert_eq!(writer.bytes_buffered(), 0);
        assert_eq!(writer.total_bytes_written(), 2248);

        let sink = writer.into_inner();
        assert_eq!(sink.into_inner().len(), 2248);
    }

    #[tokio::test]
    async fn test_async_write_trait() {
        let sink = Cursor::new(Vec::new());
        let mut writer = AsyncBufferedChunkWriter::with_capacity(sink, 512);

        let data = vec![0xCC; 1200];
        writer.write_all(&data).await.unwrap();
        writer.flush().await.unwrap();

        assert_eq!(writer.total_bytes_written(), 1200);
        let sink = writer.into_inner();
        assert_eq!(sink.into_inner().len(), 1200);
    }
}
