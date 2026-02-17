use alloc::vec;
use alloc::vec::Vec;

#[link(wasm_import_module = "platform_network")]
extern "C" {
    fn http_get(req_ptr: i32, req_len: i32, resp_ptr: i32, resp_len: i32) -> i32;
    fn http_post(req_ptr: i32, req_len: i32, resp_ptr: i32, resp_len: i32) -> i32;
    fn dns_resolve(req_ptr: i32, req_len: i32, resp_ptr: i32, resp_len: i32) -> i32;
}

#[link(wasm_import_module = "platform_storage")]
extern "C" {
    fn storage_get(key_ptr: i32, key_len: i32, value_ptr: i32, value_len: i32) -> i32;
    fn storage_set(key_ptr: i32, key_len: i32, value_ptr: i32, value_len: i32) -> i32;
}

pub fn host_http_get(request: &[u8]) -> Result<Vec<u8>, i32> {
    let mut response_buf = vec![0u8; 65536];
    let status = unsafe {
        http_get(
            request.as_ptr() as i32,
            request.len() as i32,
            response_buf.as_mut_ptr() as i32,
            response_buf.len() as i32,
        )
    };
    if status < 0 {
        return Err(status);
    }
    response_buf.truncate(status as usize);
    Ok(response_buf)
}

pub fn host_http_post(request: &[u8]) -> Result<Vec<u8>, i32> {
    let mut response_buf = vec![0u8; 65536];
    let status = unsafe {
        http_post(
            request.as_ptr() as i32,
            request.len() as i32,
            response_buf.as_mut_ptr() as i32,
            response_buf.len() as i32,
        )
    };
    if status < 0 {
        return Err(status);
    }
    response_buf.truncate(status as usize);
    Ok(response_buf)
}

pub fn host_dns_resolve(request: &[u8]) -> Result<Vec<u8>, i32> {
    let mut response_buf = vec![0u8; 4096];
    let status = unsafe {
        dns_resolve(
            request.as_ptr() as i32,
            request.len() as i32,
            response_buf.as_mut_ptr() as i32,
            response_buf.len() as i32,
        )
    };
    if status < 0 {
        return Err(status);
    }
    response_buf.truncate(status as usize);
    Ok(response_buf)
}

pub fn host_storage_get(key: &[u8]) -> Result<Vec<u8>, i32> {
    let mut value_buf = vec![0u8; 65536];
    let status = unsafe {
        storage_get(
            key.as_ptr() as i32,
            key.len() as i32,
            value_buf.as_mut_ptr() as i32,
            value_buf.len() as i32,
        )
    };
    if status < 0 {
        return Err(status);
    }
    value_buf.truncate(status as usize);
    Ok(value_buf)
}

pub fn host_storage_set(key: &[u8], value: &[u8]) -> Result<(), i32> {
    let status = unsafe {
        storage_set(
            key.as_ptr() as i32,
            key.len() as i32,
            value.as_ptr() as i32,
            value.len() as i32,
        )
    };
    if status < 0 {
        return Err(status);
    }
    Ok(())
}
