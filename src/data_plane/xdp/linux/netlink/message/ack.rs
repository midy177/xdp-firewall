use crate::data_plane::xdp::Result;
use anyhow::{Context, bail};
use std::os::fd::AsRawFd;

const NLMSG_ERROR: u16 = 2;

pub(super) fn receive_netlink_xdp_ack(socket: &impl AsRawFd) -> Result<()> {
    let mut buffer = [0_u8; 8192];
    loop {
        let len = unsafe {
            libc::recv(
                socket.as_raw_fd(),
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                0,
            )
        };
        if len < 0 {
            return Err(std::io::Error::last_os_error())
                .context("failed to receive netlink XDP replace ack");
        }
        let len = len as usize;
        if parse_netlink_xdp_ack(&buffer, len)? {
            return Ok(());
        }
    }
}

fn parse_netlink_xdp_ack(buffer: &[u8], len: usize) -> Result<bool> {
    let header_len = std::mem::size_of::<libc::nlmsghdr>();
    let mut offset = 0;
    while offset + header_len <= len {
        let header = read_unaligned::<libc::nlmsghdr>(&buffer[offset..])?;
        if header.nlmsg_len == 0 {
            bail!("received invalid zero-length netlink message");
        }
        let message_len = nla_align(header.nlmsg_len as usize);
        if offset + message_len > len {
            bail!("received truncated netlink message");
        }
        if header.nlmsg_type == NLMSG_ERROR {
            handle_netlink_error_message(buffer, offset + header_len)?;
            return Ok(true);
        }
        offset += message_len;
    }
    Ok(false)
}

fn handle_netlink_error_message(buffer: &[u8], error_offset: usize) -> Result<()> {
    let error = read_unaligned::<i32>(&buffer[error_offset..])?;
    if error == 0 {
        return Ok(());
    }
    Err(std::io::Error::from_raw_os_error(-error)).context("netlink rejected XDP replace request")
}

fn read_unaligned<T: Copy>(buffer: &[u8]) -> Result<T> {
    if buffer.len() < std::mem::size_of::<T>() {
        bail!("buffer too small for netlink value");
    }
    Ok(unsafe { std::ptr::read_unaligned(buffer.as_ptr().cast::<T>()) })
}

fn nla_align(value: usize) -> usize {
    const NLA_ALIGNTO: usize = 4;
    (value + NLA_ALIGNTO - 1) & !(NLA_ALIGNTO - 1)
}
