use std::ffi::CString;
use std::fs;
mod loopback;

fn mount(source: &str, target: &str, fstype: &str, flags: u64) -> Result<(), String> {
    let source = CString::new(source).unwrap();
    let target_c = CString::new(target).unwrap();
    let fstype = CString::new(fstype).unwrap();

    let ret = unsafe {
        libc::mount(
            source.as_ptr(),
            target_c.as_ptr(),
            fstype.as_ptr(),
            flags,
            std::ptr::null(),
        )
    };

    if ret != 0 {
        return Err(format!(
            "Failed to mount {} at {}: {}",
            source.to_str().unwrap(),
            target,
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

pub fn setup_host_env() -> Result<(), String> {
    mount("sysfs", "/sys", "sysfs", 0)?;
    // this takes like 30µs, not worth doing in a branch
    loopback::setup_loopback()?;
    fs::create_dir_all("/sys/kernel/tracing/").unwrap();
    mount("tracefs", "/sys/kernel/tracing", "tracefs", 0)?;
    mount("ramfs", "/bin", "ramfs", 0)?;
    mount("ramfs", "/tmp", "ramfs", 0)?;
    Ok(())
}
