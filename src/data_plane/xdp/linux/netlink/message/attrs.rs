#[repr(C)]
#[derive(Clone, Copy)]
struct RtAttr {
    rta_len: u16,
    rta_type: u16,
}

pub(super) fn push_attr_i32(buffer: &mut Vec<u8>, attr_type: u16, value: i32) {
    push_attr_bytes(buffer, attr_type, &value.to_ne_bytes());
}

pub(super) fn push_attr_u32(buffer: &mut Vec<u8>, attr_type: u16, value: u32) {
    push_attr_bytes(buffer, attr_type, &value.to_ne_bytes());
}

pub(super) fn push_attr_bytes(buffer: &mut Vec<u8>, attr_type: u16, value: &[u8]) {
    let attr_len = std::mem::size_of::<RtAttr>() + value.len();
    let attr = RtAttr {
        rta_len: attr_len as u16,
        rta_type: attr_type,
    };
    push_pod(buffer, &attr);
    buffer.extend_from_slice(value);
    while buffer.len() % 4 != 0 {
        buffer.push(0);
    }
}

pub(super) fn push_pod<T>(buffer: &mut Vec<u8>, value: &T) {
    let bytes = unsafe {
        std::slice::from_raw_parts(
            std::ptr::from_ref(value).cast::<u8>(),
            std::mem::size_of::<T>(),
        )
    };
    buffer.extend_from_slice(bytes);
}
