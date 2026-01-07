use std::mem;

#[repr(C)]
struct SockaddrIn {
    sin_family: libc::sa_family_t,
    sin_port: u16,
    sin_addr: libc::in_addr,
    sin_zero: [u8; 8],
}

#[repr(C)]
union IfrIfru {
    ifru_addr: libc::sockaddr,
    ifru_flags: libc::c_short,
}

#[repr(C)]
struct Ifreq {
    ifr_name: [libc::c_char; libc::IF_NAMESIZE],
    ifr_ifru: IfrIfru,
}

pub fn setup_loopback() -> Result<(), String> {
    unsafe {
        let sock = libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0);
        if sock < 0 {
            return Err(format!(
                "Failed to create socket: {}",
                std::io::Error::last_os_error()
            ));
        }

        let mut ifr_addr: Ifreq = mem::zeroed();
        let mut ifr_flags: Ifreq = mem::zeroed();

        let ifname = b"lo\0";
        ifr_addr.ifr_name[..ifname.len()].copy_from_slice(std::slice::from_raw_parts(
            ifname.as_ptr() as *const i8,
            ifname.len(),
        ));
        ifr_flags.ifr_name[..ifname.len()].copy_from_slice(std::slice::from_raw_parts(
            ifname.as_ptr() as *const i8,
            ifname.len(),
        ));

        let mut addr: SockaddrIn = mem::zeroed();
        addr.sin_family = libc::AF_INET as u16;
        addr.sin_addr.s_addr = u32::from_ne_bytes([127, 0, 0, 1]).to_be();

        ifr_addr.ifr_ifru.ifru_addr = *(&addr as *const SockaddrIn as *const libc::sockaddr);

        if libc::ioctl(sock, libc::SIOCSIFADDR.try_into().unwrap(), &ifr_addr) < 0 {
            libc::close(sock);
            return Err(format!(
                "Failed to set IP address: {}",
                std::io::Error::last_os_error()
            ));
        }

        ifr_flags.ifr_ifru.ifru_flags = (libc::IFF_UP | libc::IFF_RUNNING) as i16;

        if libc::ioctl(sock, libc::SIOCSIFFLAGS.try_into().unwrap(), &ifr_flags) < 0 {
            libc::close(sock);
            return Err(format!(
                "Failed to bring interface up: {}",
                std::io::Error::last_os_error()
            ));
        }

        libc::close(sock);
    }

    Ok(())
}
