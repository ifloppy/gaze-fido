#[cxx::bridge]
mod ffi {
    unsafe extern "C++" {
        include!("gaze_fido_window_icon.h");

        fn configure_gaze_fido_app_identity();
        fn ensure_gaze_fido_single_instance() -> bool;
        fn run_gaze_fido_application() -> i32;
    }
}

pub fn configure_app_identity() {
    ffi::configure_gaze_fido_app_identity();
}

pub fn ensure_single_instance() -> bool {
    ffi::ensure_gaze_fido_single_instance()
}

pub fn run_application() -> i32 {
    ffi::run_gaze_fido_application()
}
