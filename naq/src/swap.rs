//! A value a reload swaps while the lanes read it.

use std::sync::{PoisonError, RwLock};

/// A value read often and swapped whole now and then: each reader takes a
/// clone of the one there, so `T` is an `Arc` or as cheap to clone.
#[derive(Default)]
pub(crate) struct Swap<T>(RwLock<T>);

impl<T: Clone> Swap<T> {
    pub(crate) const fn new(value: T) -> Swap<T> {
        Swap(RwLock::new(value))
    }

    /// The value now.
    pub(crate) fn get(&self) -> T {
        self.0
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Takes `value` from now on.
    pub(crate) fn set(&self, value: T) {
        *self.0.write().unwrap_or_else(PoisonError::into_inner) = value;
    }
}

impl<T> std::fmt::Debug for Swap<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Swap").finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_reader_takes_the_value_last_set() {
        let s = Swap::new(1);
        assert_eq!(s.get(), 1);
        s.set(2);
        assert_eq!(s.get(), 2);
        assert_eq!(format!("{s:?}"), "Swap { .. }");
    }
}
