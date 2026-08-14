use crate::data_plane::xdp::Result;
use anyhow::Context;

pub(in crate::data_plane::xdp) fn monotonic_now_ns() -> Result<u64> {
    let mut ts = std::mem::MaybeUninit::<libc::timespec>::uninit();
    let result = unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, ts.as_mut_ptr()) };
    if result != 0 {
        return Err(std::io::Error::last_os_error()).context("failed to read CLOCK_MONOTONIC");
    }
    let ts = unsafe { ts.assume_init() };
    let seconds = u64::try_from(ts.tv_sec).context("CLOCK_MONOTONIC seconds are negative")?;
    let nanos = u64::try_from(ts.tv_nsec).context("CLOCK_MONOTONIC nanos are negative")?;
    seconds
        .checked_mul(1_000_000_000)
        .and_then(|value| value.checked_add(nanos))
        .context("CLOCK_MONOTONIC value overflowed")
}
