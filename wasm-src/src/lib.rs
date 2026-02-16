//! Noteva S3 图床 WASM 插件
//!
//! 拦截 image_upload_filter 钩子，将图片上传到 S3 兼容存储。
//! 支持 AWS S3、腾讯 COS、阿里 OSS、Cloudflare R2、七牛等。
//!
//! 使用宿主提供的 host_hmac_sha256 / host_sha256 完成 AWS Signature V4 签名。
//! 需要 `network`、`storage` 权限。

use std::alloc::{alloc, Layout};
use std::slice;

// ============================================================
// 宿主函数声明
// ============================================================

extern "C" {
    fn host_http_request(
        method_ptr: i32, method_len: i32,
        url_ptr: i32, url_len: i32,
        headers_ptr: i32, headers_len: i32,
        body_ptr: i32, body_len: i32,
    ) -> i32;

    fn host_log(
        level_ptr: i32, level_len: i32,
        msg_ptr: i32, msg_len: i32,
    );

    fn host_hmac_sha256(
        key_ptr: i32, key_len: i32,
        data_ptr: i32, data_len: i32,
    ) -> i32;

    fn host_sha256(
        data_ptr: i32, data_len: i32,
    ) -> i32;
}

// ============================================================
// 内存分配器
// ============================================================

#[no_mangle]
pub extern "C" fn allocate(size: i32) -> i32 {
    if size <= 0 || size > 16 * 1024 * 1024 { return 0; }
    let layout = match Layout::from_size_align(size as usize, 1) {
        Ok(l) => l,
        Err(_) => return 0,
    };
    let ptr = unsafe { alloc(layout) };
    if ptr.is_null() { 0 } else { ptr as i32 }
}

// ============================================================
// 宿主函数封装
// ============================================================

fn log(level: &str, msg: &str) {
    unsafe {
        host_log(
            level.as_ptr() as i32, level.len() as i32,
            msg.as_ptr() as i32, msg.len() as i32,
        );
    }
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Option<String> {
    let result_ptr = unsafe {
        host_hmac_sha256(
            key.as_ptr() as i32, key.len() as i32,
            data.as_ptr() as i32, data.len() as i32,
        )
    };
    if result_ptr <= 0 { return None; }
    read_result(result_ptr)
}

fn sha256(data: &[u8]) -> Option<String> {
    let result_ptr = unsafe {
        host_sha256(data.as_ptr() as i32, data.len() as i32)
    };
    if result_ptr <= 0 { return None; }
    read_result(result_ptr)
}

/// HMAC-SHA256 returning raw bytes (decoded from hex)
fn hmac_sha256_bytes(key: &[u8], data: &[u8]) -> Option<Vec<u8>> {
    let hex = hmac_sha256(key, data)?;
    hex_decode(&hex)
}

fn http_put(url: &str, headers: &str, body: &[u8]) -> Option<String> {
    let method = "PUT";
    let result_ptr = unsafe {
        host_http_request(
            method.as_ptr() as i32, method.len() as i32,
            url.as_ptr() as i32, url.len() as i32,
            headers.as_ptr() as i32, headers.len() as i32,
            body.as_ptr() as i32, body.len() as i32,
        )
    };
    if result_ptr <= 0 { return None; }
    read_result(result_ptr)
}

fn read_result(ptr: i32) -> Option<String> {
    unsafe {
        let rp = ptr as usize;
        let len_bytes = slice::from_raw_parts(rp as *const u8, 4);
        let len = u32::from_le_bytes([len_bytes[0], len_bytes[1], len_bytes[2], len_bytes[3]]) as usize;
        if len == 0 { return None; }
        let data = slice::from_raw_parts((rp + 4) as *const u8, len);
        String::from_utf8(data.to_vec()).ok()
    }
}

// ============================================================
// JSON / 编码工具
// ============================================================

fn extract_json_string(json: &str, key: &str) -> Option<String> {
    let search = format!("\"{}\"", key);
    let pos = json.find(&search)?;
    let rest = &json[pos + search.len()..];
    let colon = rest.find(':')?;
    let after = rest[colon + 1..].trim_start();
    if !after.starts_with('"') { return None; }

    let bytes = after.as_bytes();
    let mut i = 1;
    let mut result_bytes: Vec<u8> = Vec::new();
    while i < bytes.len() {
        match bytes[i] {
            b'\\' if i + 1 < bytes.len() => {
                match bytes[i + 1] {
                    b'"' => { result_bytes.push(b'"'); i += 2; }
                    b'\\' => { result_bytes.push(b'\\'); i += 2; }
                    b'n' => { result_bytes.push(b'\n'); i += 2; }
                    b'r' => { result_bytes.push(b'\r'); i += 2; }
                    b't' => { result_bytes.push(b'\t'); i += 2; }
                    b'/' => { result_bytes.push(b'/'); i += 2; }
                    _ => { result_bytes.push(b'\\'); result_bytes.push(bytes[i + 1]); i += 2; }
                }
            }
            b'"' => return String::from_utf8(result_bytes).ok(),
            b => { result_bytes.push(b); i += 1; }
        }
    }
    None
}

fn extract_json_number(json: &str, key: &str) -> Option<i64> {
    let search = format!("\"{}\"", key);
    let pos = json.find(&search)?;
    let rest = &json[pos + search.len()..];
    let colon = rest.find(':')?;
    let after = rest[colon + 1..].trim_start();
    let mut num_str = String::new();
    for ch in after.chars() {
        if ch.is_ascii_digit() || ch == '-' { num_str.push(ch); }
        else if !num_str.is_empty() { break; }
    }
    num_str.parse().ok()
}

fn escape_json_string(s: &str) -> String {
    s.replace('\\', "\\\\")
     .replace('"', "\\\"")
     .replace('\n', "\\n")
     .replace('\r', "\\r")
     .replace('\t', "\\t")
}

fn write_output(json: &str) -> i32 {
    let bytes = json.as_bytes();
    let total = 4 + bytes.len();
    let layout = match Layout::from_size_align(total, 1) {
        Ok(l) => l,
        Err(_) => return 0,
    };
    let ptr = unsafe { alloc(layout) };
    if ptr.is_null() { return 0; }
    let len_bytes = (bytes.len() as u32).to_le_bytes();
    unsafe {
        std::ptr::copy_nonoverlapping(len_bytes.as_ptr(), ptr, 4);
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), ptr.add(4), bytes.len());
    }
    ptr as i32
}

fn hex_decode(hex: &str) -> Option<Vec<u8>> {
    let bytes = hex.as_bytes();
    if bytes.len() % 2 != 0 { return None; }
    let mut result = Vec::with_capacity(bytes.len() / 2);
    for chunk in bytes.chunks(2) {
        let hi = hex_val(chunk[0])?;
        let lo = hex_val(chunk[1])?;
        result.push((hi << 4) | lo);
    }
    Some(result)
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// URL-encode a string (percent-encoding for S3 paths)
fn url_encode(s: &str) -> String {
    let mut result = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                result.push(b as char);
            }
            b'/' => result.push('/'), // Don't encode path separators
            _ => {
                result.push('%');
                result.push_str(&format!("{:02X}", b));
            }
        }
    }
    result
}

/// Base64 decode
fn base64_decode(input: &str) -> Option<Vec<u8>> {
    let input = input.trim_end_matches('=');
    let bytes = input.as_bytes();
    let mut result = Vec::with_capacity(bytes.len() * 3 / 4);
    let mut buf: u32 = 0;
    let mut bits: u32 = 0;
    for &b in bytes {
        let val = match b {
            b'A'..=b'Z' => (b - b'A') as u32,
            b'a'..=b'z' => (b - b'a' + 26) as u32,
            b'0'..=b'9' => (b - b'0' + 52) as u32,
            b'+' => 62,
            b'/' => 63,
            _ => continue,
        };
        buf = (buf << 6) | val;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            result.push((buf >> bits) as u8);
            buf &= (1 << bits) - 1;
        }
    }
    Some(result)
}

// ============================================================
// AWS Signature V4
// ============================================================

struct S3Config {
    endpoint: String,
    region: String,
    bucket: String,
    access_key: String,
    secret_key: String,
    path_prefix: String,
    custom_domain: String,
}

/// Parse host from endpoint URL (e.g. "https://s3.amazonaws.com" -> "s3.amazonaws.com")
fn parse_host(endpoint: &str) -> &str {
    let s = endpoint.strip_prefix("https://").or_else(|| endpoint.strip_prefix("http://")).unwrap_or(endpoint);
    s.split('/').next().unwrap_or(s)
}

/// Get current UTC timestamp in ISO 8601 basic format
/// Since we don't have chrono in WASM, we pass the timestamp from the hook data
fn format_amz_date(timestamp: &str) -> (String, String) {
    // timestamp is ISO 8601: "2026-02-13T14:30:00Z" or similar
    // amz_date: "20260213T143000Z"
    // date_stamp: "20260213"
    let clean: String = timestamp.chars()
        .filter(|c| c.is_ascii_digit() || *c == 'T' || *c == 'Z')
        .collect();
    // Ensure format: YYYYMMDDTHHMMSSZ
    let amz_date = if clean.len() >= 15 {
        format!("{}T{}Z", &clean[..8], &clean[9..15])
    } else {
        clean.clone()
    };
    let date_stamp = if clean.len() >= 8 {
        clean[..8].to_string()
    } else {
        clean
    };
    (amz_date, date_stamp)
}

fn sign_s3_request(
    config: &S3Config,
    object_key: &str,
    content_type: &str,
    payload_hash: &str,
    timestamp: &str,
) -> Option<(String, String)> {
    // Returns (authorization_header, amz_date)
    let (amz_date, date_stamp) = format_amz_date(timestamp);
    let host = parse_host(&config.endpoint);
    
    // Determine the actual host for the request
    // Path-style: host = endpoint_host, path = /bucket/key
    // Virtual-hosted: host = bucket.endpoint_host, path = /key
    // We use path-style for maximum compatibility
    let canonical_uri = format!("/{}/{}", url_encode(&config.bucket), url_encode(object_key));
    let canonical_querystring = "";
    
    let canonical_headers = format!(
        "content-type:{}\nhost:{}\nx-amz-content-sha256:{}\nx-amz-date:{}\n",
        content_type, host, payload_hash, amz_date
    );
    let signed_headers = "content-type;host;x-amz-content-sha256;x-amz-date";
    
    let canonical_request = format!(
        "PUT\n{}\n{}\n{}\n{}\n{}",
        canonical_uri, canonical_querystring, canonical_headers, signed_headers, payload_hash
    );
    
    let credential_scope = format!("{}/{}/s3/aws4_request", date_stamp, config.region);
    let canonical_request_hash = sha256(canonical_request.as_bytes())?;
    
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{}\n{}\n{}",
        amz_date, credential_scope, canonical_request_hash
    );
    
    // Derive signing key: HMAC chain
    let k_secret = format!("AWS4{}", config.secret_key);
    let k_date = hmac_sha256_bytes(k_secret.as_bytes(), date_stamp.as_bytes())?;
    let k_region = hmac_sha256_bytes(&k_date, config.region.as_bytes())?;
    let k_service = hmac_sha256_bytes(&k_region, b"s3")?;
    let k_signing = hmac_sha256_bytes(&k_service, b"aws4_request")?;
    
    let signature = hmac_sha256(&k_signing, string_to_sign.as_bytes())?;
    
    let authorization = format!(
        "AWS4-HMAC-SHA256 Credential={}/{}, SignedHeaders={}, Signature={}",
        config.access_key, credential_scope, signed_headers, signature
    );
    
    Some((authorization, amz_date))
}

// ============================================================
// 钩子入口：图片上传过滤器
// ============================================================

#[no_mangle]
pub extern "C" fn hook_image_upload_filter(ptr: i32, len: i32) -> i32 {
    if ptr <= 0 || len <= 0 || len > 16 * 1024 * 1024 { return 0; }

    let input = unsafe {
        let slice = slice::from_raw_parts(ptr as *const u8, len as usize);
        match std::str::from_utf8(slice) {
            Ok(s) => s,
            Err(_) => return 0,
        }
    };

    // Extract settings from hook data
    let endpoint = match extract_json_string(input, "endpoint") {
        Some(e) if !e.is_empty() => e,
        _ => {
            log("warn", "S3 plugin: no endpoint configured, skipping");
            return write_output(r#"{"handled":false}"#);
        }
    };
    let bucket = match extract_json_string(input, "bucket") {
        Some(b) if !b.is_empty() => b,
        _ => {
            log("warn", "S3 plugin: no bucket configured, skipping");
            return write_output(r#"{"handled":false}"#);
        }
    };
    let access_key = match extract_json_string(input, "access_key") {
        Some(k) if !k.is_empty() => k,
        _ => {
            log("warn", "S3 plugin: no access_key configured, skipping");
            return write_output(r#"{"handled":false}"#);
        }
    };
    let secret_key = match extract_json_string(input, "secret_key") {
        Some(k) if !k.is_empty() => k,
        _ => {
            log("warn", "S3 plugin: no secret_key configured, skipping");
            return write_output(r#"{"handled":false}"#);
        }
    };
    let region = extract_json_string(input, "region").unwrap_or_else(|| "us-east-1".to_string());
    let path_prefix = extract_json_string(input, "path_prefix").unwrap_or_else(|| "blog/images/".to_string());
    let custom_domain = extract_json_string(input, "custom_domain").unwrap_or_default();

    let config = S3Config {
        endpoint,
        region,
        bucket,
        access_key,
        secret_key,
        path_prefix,
        custom_domain,
    };

    // Extract file data
    let filename = match extract_json_string(input, "filename") {
        Some(f) => f,
        None => {
            log("error", "S3 plugin: no filename in hook data");
            return write_output(r#"{"handled":false}"#);
        }
    };
    let content_type = extract_json_string(input, "content_type")
        .unwrap_or_else(|| "application/octet-stream".to_string());
    let data_base64 = match extract_json_string(input, "data_base64") {
        Some(d) => d,
        None => {
            log("error", "S3 plugin: no data_base64 in hook data");
            return write_output(r#"{"handled":false}"#);
        }
    };

    let file_data = match base64_decode(&data_base64) {
        Some(d) => d,
        None => {
            log("error", "S3 plugin: failed to decode base64 data");
            return write_output(r#"{"handled":false}"#);
        }
    };

    let object_key = format!("{}{}", config.path_prefix, filename);
    log("info", &format!("Uploading to S3: {}/{}", config.bucket, object_key));

    // Compute payload hash
    let payload_hash = match sha256(&file_data) {
        Some(h) => h,
        None => {
            log("error", "S3 plugin: failed to compute payload hash");
            return write_output(r#"{"handled":false}"#);
        }
    };

    // Get timestamp from hook data, or use a fallback
    let timestamp = extract_json_string(input, "timestamp")
        .unwrap_or_else(|| "20260213T120000Z".to_string());

    // Sign the request
    let (authorization, amz_date) = match sign_s3_request(&config, &object_key, &content_type, &payload_hash, &timestamp) {
        Some(r) => r,
        None => {
            log("error", "S3 plugin: failed to sign request");
            return write_output(r#"{"handled":false}"#);
        }
    };

    let host = parse_host(&config.endpoint);
    let url = format!("{}/{}/{}", config.endpoint.trim_end_matches('/'), config.bucket, url_encode(&object_key));

    let headers = format!(
        r#"{{"Content-Type":"{}","Host":"{}","x-amz-content-sha256":"{}","x-amz-date":"{}","Authorization":"{}"}}"#,
        escape_json_string(&content_type),
        escape_json_string(host),
        escape_json_string(&payload_hash),
        escape_json_string(&amz_date),
        escape_json_string(&authorization)
    );

    let response = match http_put(&url, &headers, &file_data) {
        Some(r) => r,
        None => {
            log("error", "S3 plugin: HTTP PUT request failed");
            return write_output(r#"{"handled":false}"#);
        }
    };

    // Check response status
    let status = extract_json_number(&response, "status").unwrap_or(0);
    if status != 200 && status != 201 {
        let body = extract_json_string(&response, "body").unwrap_or_default();
        let preview_end = {
            let max = body.len().min(200);
            let mut end = max;
            while end > 0 && !body.is_char_boundary(end) { end -= 1; }
            end
        };
        log("error", &format!("S3 upload failed (status {}): {}", status, &body[..preview_end]));
        return write_output(r#"{"handled":false}"#);
    }

    // Build the public URL
    let public_url = if !config.custom_domain.is_empty() {
        format!("{}/{}", config.custom_domain.trim_end_matches('/'), url_encode(&object_key))
    } else {
        format!("{}/{}/{}", config.endpoint.trim_end_matches('/'), config.bucket, url_encode(&object_key))
    };

    log("info", &format!("S3 upload success: {}", public_url));

    let output = format!(
        r#"{{"handled":true,"url":"{}","filename":"{}"}}"#,
        escape_json_string(&public_url),
        escape_json_string(&filename)
    );
    write_output(&output)
}

// ============================================================
// 钩子入口：插件自定义动作（连通性测试）
// ============================================================

#[no_mangle]
pub extern "C" fn hook_plugin_action(ptr: i32, len: i32) -> i32 {
    if ptr <= 0 || len <= 0 || len > 1024 * 1024 { return 0; }

    let input = unsafe {
        let slice = slice::from_raw_parts(ptr as *const u8, len as usize);
        match std::str::from_utf8(slice) {
            Ok(s) => s,
            Err(_) => return 0,
        }
    };

    let target_plugin = extract_json_string(input, "plugin_id").unwrap_or_default();
    if target_plugin != "s3-image-upload" { return 0; }

    let action = extract_json_string(input, "action").unwrap_or_default();
    match action.as_str() {
        "test_connection" => action_test_connection(input),
        _ => 0,
    }
}

fn action_test_connection(input: &str) -> i32 {
    let endpoint = match extract_json_string(input, "endpoint") {
        Some(e) if !e.is_empty() => e,
        _ => return write_output(r#"{"success":false,"message":"未配置 Endpoint"}"#),
    };
    let bucket = match extract_json_string(input, "bucket") {
        Some(b) if !b.is_empty() => b,
        _ => return write_output(r#"{"success":false,"message":"未配置 Bucket"}"#),
    };
    let access_key = match extract_json_string(input, "access_key") {
        Some(k) if !k.is_empty() => k,
        _ => return write_output(r#"{"success":false,"message":"未配置 Access Key"}"#),
    };
    let secret_key = match extract_json_string(input, "secret_key") {
        Some(k) if !k.is_empty() => k,
        _ => return write_output(r#"{"success":false,"message":"未配置 Secret Key"}"#),
    };
    let region = extract_json_string(input, "region").unwrap_or_else(|| "us-east-1".to_string());

    let config = S3Config {
        endpoint: endpoint.clone(),
        region,
        bucket: bucket.clone(),
        access_key,
        secret_key,
        path_prefix: String::new(),
        custom_domain: String::new(),
    };

    // Test: upload a tiny test file, then check response
    let test_key = ".noteva-connection-test";
    let test_data = b"ok";
    let content_type = "text/plain";

    let payload_hash = match sha256(test_data) {
        Some(h) => h,
        None => return write_output(r#"{"success":false,"message":"SHA256 计算失败"}"#),
    };

    // Use current-ish timestamp (from hook data if available)
    let timestamp = extract_json_string(input, "timestamp")
        .unwrap_or_else(|| "20260213T120000Z".to_string());

    let (authorization, amz_date) = match sign_s3_request(&config, test_key, content_type, &payload_hash, &timestamp) {
        Some(r) => r,
        None => return write_output(r#"{"success":false,"message":"签名计算失败"}"#),
    };

    let host = parse_host(&config.endpoint);
    let url = format!("{}/{}/{}", endpoint.trim_end_matches('/'), bucket, test_key);

    let headers = format!(
        r#"{{"Content-Type":"{}","Host":"{}","x-amz-content-sha256":"{}","x-amz-date":"{}","Authorization":"{}"}}"#,
        escape_json_string(content_type),
        escape_json_string(host),
        escape_json_string(&payload_hash),
        escape_json_string(&amz_date),
        escape_json_string(&authorization)
    );

    let response = match http_put(&url, &headers, test_data) {
        Some(r) => r,
        None => return write_output(r#"{"success":false,"message":"HTTP 请求失败，请检查 Endpoint 是否正确"}"#),
    };

    let status = extract_json_number(&response, "status").unwrap_or(0);
    if status == 200 || status == 201 {
        log("info", "S3 connection test passed");
        write_output(r#"{"success":true,"message":"连接成功"}"#)
    } else {
        let body = extract_json_string(&response, "body").unwrap_or_default();
        let preview_end = {
            let max = body.len().min(150);
            let mut end = max;
            while end > 0 && !body.is_char_boundary(end) { end -= 1; }
            end
        };
        let msg = format!("上传测试失败 (HTTP {}): {}", status, &body[..preview_end]);
        log("error", &msg);
        let output = format!(
            r#"{{"success":false,"message":"{}"}}"#,
            escape_json_string(&msg)
        );
        write_output(&output)
    }
}
