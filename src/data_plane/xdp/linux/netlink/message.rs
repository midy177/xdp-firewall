use crate::data_plane::xdp::{Result, XdpAttachMode};
use anyhow::{Context, bail};
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd};

mod ack;
mod attrs;

use ack::receive_netlink_xdp_ack;
use attrs::{push_attr_bytes, push_attr_i32, push_attr_u32, push_pod};

const NLM_F_REQUEST: u16 = 1;
const NLM_F_ACK: u16 = 4;
const RTM_SETLINK: u16 = 19;
const IFLA_XDP: u16 = 43;
const NLA_F_NESTED: u16 = 1 << 15;
const IFLA_XDP_FD: u16 = 1;
const IFLA_XDP_FLAGS: u16 = 3;
const IFLA_XDP_EXPECTED_FD: u16 = 8;
const XDP_FLAGS_UPDATE_IF_NOEXIST: u32 = 1;
const XDP_FLAGS_SKB_MODE: u32 = 2;
const XDP_FLAGS_DRV_MODE: u32 = 4;
const XDP_FLAGS_REPLACE: u32 = 16;

pub(super) fn set_xdp_fd(
    if_index: i32,
    fd: Option<BorrowedFd<'_>>,
    expected_fd: Option<BorrowedFd<'_>>,
    mode: XdpAttachMode,
) -> Result<()> {
    let xdp_attrs = build_xdp_attrs(fd, expected_fd, mode);
    let message = build_setlink_message(if_index, &xdp_attrs)?;
    let socket = open_netlink_route_socket()?;
    send_netlink_xdp_message(&socket, &message)?;
    receive_netlink_xdp_ack(&socket)
}

fn build_xdp_attrs(
    fd: Option<BorrowedFd<'_>>,
    expected_fd: Option<BorrowedFd<'_>>,
    mode: XdpAttachMode,
) -> Vec<u8> {
    let mut attrs = Vec::new();
    push_attr_i32(&mut attrs, IFLA_XDP_FD, fd.map_or(-1, |fd| fd.as_raw_fd()));
    push_attr_u32(
        &mut attrs,
        IFLA_XDP_FLAGS,
        xdp_attach_flags(mode, expected_fd),
    );
    if let Some(expected_fd) = expected_fd {
        push_attr_i32(&mut attrs, IFLA_XDP_EXPECTED_FD, expected_fd.as_raw_fd());
    }
    attrs
}

fn xdp_attach_flags(mode: XdpAttachMode, expected_fd: Option<BorrowedFd<'_>>) -> u32 {
    let mode_flags = match mode {
        XdpAttachMode::Driver => XDP_FLAGS_DRV_MODE,
        XdpAttachMode::Skb => XDP_FLAGS_SKB_MODE,
        XdpAttachMode::Auto => 0,
    };
    let mut flags = mode_flags | XDP_FLAGS_UPDATE_IF_NOEXIST;
    if expected_fd.is_some() {
        flags |= XDP_FLAGS_REPLACE;
    }
    flags
}

fn build_setlink_message(if_index: i32, xdp_attrs: &[u8]) -> Result<Vec<u8>> {
    let mut payload = Vec::new();
    let mut if_info = unsafe { std::mem::zeroed::<libc::ifinfomsg>() };
    if_info.ifi_family = libc::AF_UNSPEC as u8;
    if_info.ifi_index = if_index;
    push_pod(&mut payload, &if_info);
    push_attr_bytes(&mut payload, IFLA_XDP | NLA_F_NESTED, xdp_attrs);

    let header_len = std::mem::size_of::<libc::nlmsghdr>();
    let mut message = Vec::with_capacity(header_len + payload.len());
    let header = libc::nlmsghdr {
        nlmsg_len: u32::try_from(header_len + payload.len())
            .context("netlink XDP message is too large")?,
        nlmsg_type: RTM_SETLINK,
        nlmsg_flags: NLM_F_REQUEST | NLM_F_ACK,
        nlmsg_seq: 1,
        nlmsg_pid: 0,
    };
    push_pod(&mut message, &header);
    message.extend_from_slice(&payload);
    Ok(message)
}

fn open_netlink_route_socket() -> Result<OwnedFd> {
    let socket = unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_RAW, libc::NETLINK_ROUTE) };
    if socket < 0 {
        return Err(std::io::Error::last_os_error()).context("failed to open netlink socket");
    }
    owned_fd_from_raw_fd_checked(socket)
}

fn send_netlink_xdp_message(socket: &OwnedFd, message: &[u8]) -> Result<()> {
    let sent = unsafe {
        libc::send(
            socket.as_raw_fd(),
            message.as_ptr().cast(),
            message.len(),
            0,
        )
    };
    if sent < 0 {
        return Err(std::io::Error::last_os_error())
            .context("failed to send netlink XDP replace request");
    }
    Ok(())
}

fn owned_fd_from_raw_fd_checked(fd: i32) -> Result<OwnedFd> {
    if fd < 0 {
        bail!("invalid raw fd {fd}");
    }
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}
