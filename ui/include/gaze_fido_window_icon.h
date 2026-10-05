#pragma once

#include <QApplication>
#include <QByteArray>
#include <QDir>
#include <QFile>
#include <QIcon>
#include <QLocalServer>
#include <QLocalSocket>
#include <QDebug>
#include <QWindow>
#include <QString>
#include <sys/stat.h>

inline QApplication *gaze_fido_application() {
  static int argc = 1;
  static char application_name[] = "gaze-fido-ui";
  static char *argv[] = {application_name, nullptr};
  static QApplication application(argc, argv);
  return &application;
}

inline void configure_gaze_fido_app_identity() {
  QApplication *application = gaze_fido_application();
  application->setOrganizationName(QStringLiteral("GazeFido"));
  application->setApplicationName(QStringLiteral("Gaze FIDO"));
  application->setApplicationDisplayName(QStringLiteral("Gaze FIDO"));
  application->setQuitOnLastWindowClosed(false);
  QGuiApplication::setWindowIcon(QIcon::fromTheme(QStringLiteral("security-high")));
  QGuiApplication::setDesktopFileName(QStringLiteral("org.gazefido.gazefido"));
}

inline bool gaze_fido_activate_existing(const QString &server_name) {
  QLocalSocket socket;
  socket.connectToServer(server_name);
  if (!socket.waitForConnected(500)) {
    return false;
  }
  socket.disconnectFromServer();
  return true;
}

inline bool gaze_fido_is_socket(const QString &server_name) {
  const QByteArray native_name = QFile::encodeName(server_name);
  struct stat endpoint_status {};
  return ::lstat(native_name.constData(), &endpoint_status) == 0 &&
         S_ISSOCK(endpoint_status.st_mode);
}

inline void gaze_fido_raise_manager_window(QApplication *application) {
  for (QWindow *window : application->topLevelWindows()) {
    if (window->objectName() != QStringLiteral("gazeFidoManagerWindow")) {
      continue;
    }
    window->showNormal();
    window->raise();
    window->requestActivate();
    return;
  }
}

inline bool ensure_gaze_fido_single_instance() {
  const QString runtime_dir = qEnvironmentVariable("XDG_RUNTIME_DIR");
  if (runtime_dir.isEmpty()) {
    qWarning() << "Cannot start Gaze FIDO UI without XDG_RUNTIME_DIR";
    return false;
  }

  const QString server_name =
      QDir(runtime_dir).filePath(QStringLiteral("gaze-fido-ui-instance"));
  auto *server = new QLocalServer();
  // XDG_RUNTIME_DIR is already private to this user. Do not set
  // UserAccessOption: Qt's Unix implementation stages permissioned sockets
  // under a temporary name and renames them over the requested path, which
  // can replace an active instance's endpoint during a second launch.

  if (!server->listen(server_name)) {
    if (gaze_fido_activate_existing(server_name)) {
      delete server;
      return false;
    }

    if (!gaze_fido_is_socket(server_name) ||
        !QLocalServer::removeServer(server_name) || !server->listen(server_name)) {
      if (gaze_fido_activate_existing(server_name)) {
        delete server;
        return false;
      }
      qWarning() << "Cannot claim Gaze FIDO UI instance socket:" << server_name;
      delete server;
      return false;
    }
  }

  // Claim the endpoint before constructing QApplication. Duplicate launches
  // can notify the primary instance and exit without initializing Qt Widgets.
  QApplication *application = gaze_fido_application();
  server->setParent(application);
  QFile::setPermissions(server_name,
                        QFileDevice::ReadOwner | QFileDevice::WriteOwner);

  QObject::connect(server, &QLocalServer::newConnection, server,
                   [server, application]() {
                     while (server->hasPendingConnections()) {
                       QLocalSocket *client = server->nextPendingConnection();
                       if (!client) {
                         continue;
                       }
                       client->disconnectFromServer();
                       client->deleteLater();
                       gaze_fido_raise_manager_window(application);
                     }
                   });
  return true;
}

inline int run_gaze_fido_application() {
  return gaze_fido_application()->exec();
}
