#[cxx::bridge]
mod ffi {
    unsafe extern "C++" {
        include!("gaze_fido_window_icon.h");

        fn configure_gaze_fido_app_identity();
        fn run_gaze_fido_application() -> i32;
    }
}

pub fn configure_app_identity() {
    ffi::configure_gaze_fido_app_identity();
}

pub fn run_application() -> i32 {
    ffi::run_gaze_fido_application()
}
