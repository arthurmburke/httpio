use std::sync::{
    Arc, Weak,
    atomic::{AtomicBool, Ordering},
};

#[derive(Clone)]
pub struct Signal {
    inner: Arc<Inner>,
}

struct Inner {
    state: Arc<AtomicBool>,
}

#[derive(Clone)]
pub struct SignalHandle {
    state: Arc<AtomicBool>,
    owner: Weak<Inner>,
}

impl Signal {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Inner {
                state: Arc::new(AtomicBool::new(false)),
            }),
        }
    }

    pub fn downgrade(&self) -> SignalHandle {
        SignalHandle {
            state: Arc::clone(&self.inner.state),
            owner: Arc::downgrade(&self.inner),
        }
    }

    pub fn get(&self) -> bool {
        self.inner.state.load(Ordering::Acquire)
    }
}

impl Drop for Inner {
    fn drop(&mut self) {
        // Called when the last Signal is dropped.
        self.state.store(true, Ordering::Release);
    }
}

impl SignalHandle {
    pub fn get(&self) -> bool {
        self.state.load(Ordering::Acquire)
    }

    pub fn set(&self, value: bool) {
        self.state.store(value, Ordering::Release);
    }

    pub fn is_alive(&self) -> bool {
        self.owner.strong_count() > 0
    }
}
