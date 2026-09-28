#pragma once

#include <QApplication>
#include <QIcon>
#include <QString>

inline QApplication *gaze_fido_application() {
  static int argc = 1;
  static char application_name[] = "gaze-fido-ui";
  static char *argv[] = {application_name, nullptr};
  static QApplication application(argc, argv);
  return &application;
}

inline void configure_gaze_fido_app_identity() {
  QApplication *application = gaze_fido_application();
  application->setApplicationName(QStringLiteral("Gaze FIDO"));
  application->setApplicationDisplayName(QStringLiteral("Gaze FIDO"));
  application->setQuitOnLastWindowClosed(false);
  QGuiApplication::setWindowIcon(QIcon::fromTheme(QStringLiteral("security-high")));
  QGuiApplication::setDesktopFileName(QStringLiteral("org.gazefido.gazefido"));
}

inline int run_gaze_fido_application() {
  return gaze_fido_application()->exec();
}
