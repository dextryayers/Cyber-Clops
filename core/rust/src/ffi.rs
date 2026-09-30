use std::ffi::{CStr, CString};
use std::os::raw::c_char;

// Minimal C ABI used by GUI Topbar and native tests.
// JSON out, caller frees with clops_free.

#[no_mangle]
pub extern "C" fn clops_accel_json() -> *mut c_char {
  let info = crate::accel::detect();
  let s = serde_json::to_string(&info).unwrap_or_else(|_| "{}".into());
  CString::new(s).unwrap().into_raw()
}

#[no_mangle]
pub extern "C" fn clops_version() -> *mut c_char {
  CString::new(crate::VERSION).unwrap().into_raw()
}

#[no_mangle]
pub unsafe extern "C" fn clops_free(p: *mut c_char) {
  if !p.is_null() {
    let _ = CString::from_raw(p);
  }
}

#[no_mangle]
pub unsafe extern "C" fn clops_scope_check(scope_json: *const c_char, target: *const c_char) -> i32 {
  if scope_json.is_null() || target.is_null() {
    return 0;
  }
  let sj = CStr::from_ptr(scope_json).to_string_lossy();
  let t = CStr::from_ptr(target).to_string_lossy();
  match serde_json::from_str::<crate::scope::Scope>(&sj) {
    Ok(s) => {
      if s.is_allowed(&t) {
        1
      } else {
        0
      }
    }
    Err(_) => 0,
  }
}
