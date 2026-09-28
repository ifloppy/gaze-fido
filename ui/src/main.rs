mod backend;
mod window_icon;

use cxx_qt_lib::{QQmlApplicationEngine, QQuickStyle, QString, QUrl};
use std::env;

fn main() {
    if env::var_os("QT_QUICK_CONTROLS_STYLE").is_none()
        && env::var("XDG_CURRENT_DESKTOP")
            .unwrap_or_default()
            .to_ascii_lowercase()
            .split(':')
            .any(|desktop| desktop.contains("kde") || desktop.contains("plasma"))
    {
        QQuickStyle::set_style(&QString::from("org.kde.desktop"));
    }
    window_icon::configure_app_identity();

    let mut engine = QQmlApplicationEngine::new();
    if let Some(engine) = engine.as_mut() {
        engine.load(&QUrl::from(
            "qrc:/qt/qml/org/gazefido/companion/src/qml/Main.qml",
        ));
    }

    window_icon::run_application();
}
