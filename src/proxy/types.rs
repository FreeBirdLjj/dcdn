use tokio::io::{AsyncRead, AsyncWrite};

/// The dynamic stream type returned by dialers (tokio 1.53 removed the AsyncReadWrite
/// trait; a trait object allows only one non-auto trait, so use the standard pattern of
/// a combining trait with a blanket impl)
pub trait DynStream: AsyncRead + AsyncWrite + Unpin + Send + std::fmt::Debug {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send + std::fmt::Debug> DynStream for T {}

pub type DynStreamBox = Box<dyn DynStream>;
