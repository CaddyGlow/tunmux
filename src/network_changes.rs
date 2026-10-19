//! Native notifications only mark dirty state; network effects stay on the worker.
use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    Arc,
};
use std::time::{Duration, Instant};

pub struct NetworkChanges {
    generation: Arc<AtomicU64>,
    stopped: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}
impl NetworkChanges {
    pub fn start() -> Self {
        let generation = Arc::new(AtomicU64::new(0));
        let stopped = Arc::new(AtomicBool::new(false));
        #[cfg(target_os = "macos")]
        let thread = {
            let generation = generation.clone();
            let stopped = stopped.clone();
            std::thread::Builder::new()
                .name("tunmux-network-events".into())
                .spawn(move || {
                    if let Err(error) = native::watch(generation, stopped) {
                        tracing::warn!(%error, "network_notifications_unavailable_using_polling");
                    }
                })
                .ok()
        };
        #[cfg(not(target_os = "macos"))]
        let thread = None;
        Self {
            generation,
            stopped,
            thread,
        }
    }
    pub fn generation(&self) -> u64 {
        self.generation.load(Ordering::Acquire)
    }
}
impl Drop for NetworkChanges {
    fn drop(&mut self) {
        self.stopped.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// Coalesce bursts without allowing continuous notifications to starve reconciliation.
pub struct Debounce {
    generation: u64,
    first: Option<Instant>,
    last: Instant,
    poll: Instant,
}
impl Debounce {
    pub fn new(now: Instant) -> Self {
        Self {
            generation: 0,
            first: None,
            last: now,
            poll: now + Duration::from_secs(10),
        }
    }
    pub fn due(&mut self, generation: u64, now: Instant) -> bool {
        if generation != self.generation {
            self.generation = generation;
            self.first.get_or_insert(now);
            self.last = now;
        }
        let event = self.first.is_some_and(|first| {
            now.duration_since(self.last) >= Duration::from_millis(500)
                || now.duration_since(first) >= Duration::from_secs(2)
        });
        if event || now >= self.poll {
            self.first = None;
            self.poll = now + Duration::from_secs(10);
            true
        } else {
            false
        }
    }
    pub fn confirm_soon(&mut self, now: Instant) {
        self.poll = self.poll.min(now + Duration::from_secs(1));
    }
}

#[cfg(target_os = "macos")]
mod native {
    use super::*;
    use std::ffi::{c_char, c_void};
    type Ref = *const c_void;
    #[repr(C)]
    struct Context {
        version: isize,
        info: *mut c_void,
        retain: Ref,
        release: Ref,
        description: Ref,
    }
    #[link(name = "SystemConfiguration", kind = "framework")]
    unsafe extern "C" {
        fn SCDynamicStoreCreate(
            allocator: Ref,
            name: Ref,
            callback: extern "C" fn(Ref, Ref, *mut c_void),
            context: *mut Context,
        ) -> Ref;
        fn SCDynamicStoreSetNotificationKeys(store: Ref, keys: Ref, patterns: Ref) -> u8;
        fn SCDynamicStoreCreateRunLoopSource(allocator: Ref, store: Ref, order: isize) -> Ref;
    }
    #[link(name = "CoreFoundation", kind = "framework")]
    unsafe extern "C" {
        fn CFStringCreateWithCString(allocator: Ref, text: *const c_char, encoding: u32) -> Ref;
        fn CFArrayCreate(allocator: Ref, values: *const Ref, count: isize, callbacks: Ref) -> Ref;
        fn CFRelease(value: Ref);
        fn CFRunLoopGetCurrent() -> Ref;
        fn CFRunLoopAddSource(run_loop: Ref, source: Ref, mode: Ref);
        fn CFRunLoopRemoveSource(run_loop: Ref, source: Ref, mode: Ref);
        fn CFRunLoopRunInMode(mode: Ref, seconds: f64, return_after_source: u8) -> i32;
        static kCFRunLoopDefaultMode: Ref;
    }
    struct Owned(Ref);
    impl Owned {
        fn new(value: Ref) -> anyhow::Result<Self> {
            anyhow::ensure!(!value.is_null(), "SystemConfiguration allocation failed");
            Ok(Self(value))
        }
    }
    impl Drop for Owned {
        fn drop(&mut self) {
            unsafe { CFRelease(self.0) }
        }
    }
    extern "C" fn changed(_: Ref, _: Ref, info: *mut c_void) {
        // The Arc lives until the source and store are released on this same thread.
        let generation = unsafe { &*(info as *const AtomicU64) };
        generation.fetch_add(1, Ordering::Release);
    }
    pub(super) fn watch(
        generation: Arc<AtomicU64>,
        stopped: Arc<AtomicBool>,
    ) -> anyhow::Result<()> {
        let null = std::ptr::null();
        unsafe {
            let name = Owned::new(CFStringCreateWithCString(
                null,
                c"tunmux".as_ptr(),
                0x08000100,
            ))?;
            let mut context = Context {
                version: 0,
                info: Arc::as_ptr(&generation).cast_mut().cast(),
                retain: null,
                release: null,
                description: null,
            };
            let store = Owned::new(SCDynamicStoreCreate(null, name.0, changed, &mut context))?;
            let pattern = Owned::new(CFStringCreateWithCString(
                null,
                c"State:/Network/.*".as_ptr(),
                0x08000100,
            ))?;
            let patterns = Owned::new(CFArrayCreate(null, &pattern.0, 1, null))?;
            anyhow::ensure!(
                SCDynamicStoreSetNotificationKeys(store.0, null, patterns.0) != 0,
                "cannot subscribe to network changes"
            );
            let source = Owned::new(SCDynamicStoreCreateRunLoopSource(null, store.0, 0))?;
            let run_loop = CFRunLoopGetCurrent();
            CFRunLoopAddSource(run_loop, source.0, kCFRunLoopDefaultMode);
            while !stopped.load(Ordering::Acquire) {
                CFRunLoopRunInMode(kCFRunLoopDefaultMode, 0.25, 1);
            }
            CFRunLoopRemoveSource(run_loop, source.0, kCFRunLoopDefaultMode);
        }
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn debounce_and_poll_are_bounded() {
        let start = Instant::now();
        let mut d = Debounce::new(start);
        assert!(!d.due(1, start));
        assert!(!d.due(2, start + Duration::from_millis(400)));
        assert!(d.due(2, start + Duration::from_millis(900)));
        assert!(!d.due(2, start + Duration::from_secs(9)));
        assert!(d.due(2, start + Duration::from_secs(11)));
    }
    #[test]
    fn continuous_events_do_not_starve() {
        let start = Instant::now();
        let mut d = Debounce::new(start);
        for n in 0..20 {
            assert!(!d.due(n + 1, start + Duration::from_millis(n * 100)));
        }
        assert!(d.due(21, start + Duration::from_secs(2)));
    }
}
