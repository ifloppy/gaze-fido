use cxx_qt_build::{CxxQtBuilder, QmlModule};

fn main() {
    CxxQtBuilder::new_qml_module(
        QmlModule::new("org.gazefido.companion").qml_file("src/qml/Main.qml"),
    )
    .files(["src/backend.rs", "src/window_icon.rs"])
    .qt_module("Widgets")
    .include_dir("include")
    .build();
}
