use super::*;
use std::os::fd::{AsFd, OwnedFd};
use tracing::warn;

mod attach;
mod message;
mod programs;

pub(super) use attach::attach_program;
use message::set_xdp_fd;

pub(super) struct DirectNetlinkLink {
    interface: String,
    if_index: i32,
    prog_fd: OwnedFd,
    mode: XdpAttachMode,
}

impl Drop for DirectNetlinkLink {
    fn drop(&mut self) {
        if let Err(err) = set_xdp_fd(self.if_index, None, Some(self.prog_fd.as_fd()), self.mode) {
            warn!(
                interface = %self.interface,
                mode = %self.mode.as_str(),
                error = %err,
                "failed to detach direct replacement XDP link"
            );
        }
    }
}
