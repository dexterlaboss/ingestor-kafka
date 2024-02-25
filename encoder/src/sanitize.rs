
use thiserror::Error;

#[derive(PartialEq, Debug, Error, Eq, Clone)]
pub enum SanitizeError {
    #[error("index out of bounds")]
    IndexOutOfBounds,
    // #[error("value out of bounds")]
    // ValueOutOfBounds,
    #[error("invalid value")]
    InvalidValue,
}

/// A trait for sanitizing values and members of over-the-wire messages.
pub trait Sanitize {
    fn sanitize(&self) -> Result<(), SanitizeError> {
        Ok(())
    }
}

impl<T: Sanitize> Sanitize for Vec<T> {
    fn sanitize(&self) -> Result<(), SanitizeError> {
        for x in self.iter() {
            x.sanitize()?;
        }
        Ok(())
    }
}