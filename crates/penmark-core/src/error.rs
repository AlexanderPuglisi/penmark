use thiserror::Error;

/// Everything that can go wrong in the core library.
#[derive(Debug, Error)]
pub enum Error {
    /// Reading or writing a file failed.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// A `.penmark` file is malformed or not a PenMark signature.
    #[error("invalid .penmark file: {0}")]
    Format(String),

    /// A value given to the library is not acceptable (too long, wrong key...).
    #[error("invalid input: {0}")]
    Input(String),

    /// The operating system could not provide random bytes.
    #[error("system random generator unavailable: {0}")]
    Random(String),
}

/// Result type used across the core library.
pub type Result<T> = std::result::Result<T, Error>;
