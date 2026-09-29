// qtc-host -- minimal in-process host for qt-commander.
//
// Builds a small Qt Widgets window with fixed objectNames and starts the
// qt-commander RPC service *in-process* by calling qt_commander_init()
// directly -- no injection.  This exercises the embed/static path end to end:
//
//   qtc.py host start --session host --link static|dll
//   qtc.py attach --session host
//   qtc.py tree --session host ...
//
// Modes:
//   static (default, needs QTC_STATIC=ON): qt_commander_init linked at build
//          time (qt-commander-static.lib).
//   dll:     resolved via QLibrary from libqt-commander.dll next to this exe.
#include <QApplication>
#include <QCheckBox>
#include <QCommandLineOption>
#include <QCommandLineParser>
#include <QDockWidget>
#include <QFile>
#include <QLabel>
#include <QLibrary>
#include <QLineEdit>
#include <QMainWindow>
#include <QPushButton>
#include <QTabWidget>
#include <QTimer>
#include <QVBoxLayout>
#include <QWidget>

#include <cstdio>
#include <cstring>
#include <random>

#include "api.h"  // InitParams + qt_commander_init (declaration only)

namespace {

QString g_session = "host";
QString g_portDir;
QString g_dllPath;
bool g_useDll = false;

void logLine(const QString& line)
{
    const QByteArray utf8 = line.toUtf8();
    fwrite(utf8.constData(), 1, size_t(utf8.size()), stdout);
    fputc('\n', stdout);
    fflush(stdout);
}

QString randomToken()
{
    static const char hex[] = "0123456789abcdef";
    std::mt19937_64 rng(std::random_device{}());
    QString token;
    for (int i = 0; i < 64; ++i)
        token += hex[rng() % 16];
    return token;
}

QMainWindow* buildWindow()
{
    auto* win = new QMainWindow;
    win->setObjectName("host_mainwindow");
    win->setWindowTitle("qtc-host");
    win->resize(640, 480);

    auto* central = new QWidget(win);
    central->setObjectName("host_central");
    auto* layout = new QVBoxLayout(central);

    auto* label = new QLabel("qtc-host ready", central);
    label->setObjectName("host_label");
    layout->addWidget(label);

    auto* edit = new QLineEdit(central);
    edit->setObjectName("host_lineedit");
    edit->setPlaceholderText("type here");
    layout->addWidget(edit);

    auto* button = new QPushButton("host_button", central);
    button->setObjectName("host_button");
    layout->addWidget(button);

    auto* check = new QCheckBox("check me", central);
    check->setObjectName("host_check");
    layout->addWidget(check);

    // -- quickShot verification rig ------------------------------------
    // Hidden tab page: page two is not current, so host_tab2_target is
    // invisible until quickShot switches the tab (how="tab").
    auto* tabs = new QTabWidget(central);
    tabs->setObjectName("host_tabs");
    auto* page1 = new QWidget(tabs);
    page1->setObjectName("host_tab1");
    page1->setLayout(new QVBoxLayout(page1));
    auto* page2 = new QWidget(tabs);
    page2->setObjectName("host_tab2");
    auto* page2Lay = new QVBoxLayout(page2);
    auto* tab2Target = new QLabel("tab two target", page2);
    tab2Target->setObjectName("host_tab2_target");
    page2Lay->addWidget(tab2Target);
    tabs->addTab(page1, "one");
    tabs->addTab(page2, "two");
    tabs->setCurrentIndex(0);
    layout->addWidget(tabs);

    // Hidden dock: closed right after being docked; its body is reachable
    // only after a reveal (QDockWidget path -> how="dock-action").
    auto* dock = new QDockWidget("host dock", win);
    dock->setObjectName("host_dock");
    auto* dockBody = new QWidget(dock);
    dockBody->setObjectName("host_dock_body");
    auto* dockLay = new QVBoxLayout(dockBody);
    auto* dockTarget = new QLabel("dock target", dockBody);
    dockTarget->setObjectName("host_dock_target");
    dockLay->addWidget(dockTarget);
    dock->setWidget(dockBody);
    win->addDockWidget(Qt::RightDockWidgetArea, dock);
    dock->hide();

    layout->addStretch(1);
    win->setCentralWidget(central);

    // Never-shown top-level window: how="window-show" path.  Deliberately
    // unparented: a parented QWidget is a child widget, not a window, and
    // the window-show scenario would stop exercising that branch.
    auto* hiddenWin = new QWidget;
    hiddenWin->setObjectName("host_hiddenwin");
    hiddenWin->setWindowTitle("host hidden window");
    hiddenWin->resize(240, 120);
    auto* hwLay = new QVBoxLayout(hiddenWin);
    auto* hwTarget = new QLabel("hidden window target", hiddenWin);
    hwTarget->setObjectName("host_hiddenwin_target");
    hwLay->addWidget(hwTarget);
    // Give the never-shown window a native handle WITHOUT showing it: the
    // scanner's collectRoots() skips handle-less windows (the winId() crash
    // guard), so without this the target would be undiscoverable by find.
    // A created-but-hidden handle is exactly the state a shown-then-hidden
    // window is in, which is the realistic scenario under test.  Safe for
    // a plain QWidget (the guard exists for QQuickWidget offscreen windows).
    hiddenWin->winId();

    return win;
}

int callInit()
{
    const QString portFile = g_portDir + "/" + g_session + ".port.txt";
    InitParams params{};
    params.version = INIT_PARAMS_VERSION;
    params.total_size = INIT_PARAMS_TOTAL_SIZE;
    std::strncpy(params.workspace_path, g_portDir.toLocal8Bit().constData(),
                 sizeof(params.workspace_path) - 1);
    std::strncpy(params.session_id, g_session.left(12).toLocal8Bit().constData(),
                 sizeof(params.session_id) - 1);
    std::strncpy(params.token, randomToken().toLocal8Bit().constData(),
                 sizeof(params.token) - 1);
    std::strncpy(params.port_file_path, portFile.toLocal8Bit().constData(),
                 sizeof(params.port_file_path) - 1);

    int rc = -1;
    if (g_useDll) {
        QLibrary lib(g_dllPath);
        if (!lib.load()) {
            logLine(QString("QTC_HOST_INIT_FAILED reason=library-load error=%1 dll=%2")
                        .arg(lib.errorString(), g_dllPath));
            return 3;
        }
        auto init = reinterpret_cast<int (*)(const InitParams*)>(
            lib.resolve("qt_commander_init"));
        if (!init) {
            logLine("QTC_HOST_INIT_FAILED reason=export-not-found qt_commander_init");
            return 3;
        }
        rc = init(&params);
    } else {
#ifdef QTC_HOST_LINK_STATIC
        rc = qt_commander_init(&params);
#else
        logLine("QTC_HOST_INIT_FAILED reason=built-without-static "
                "(rebuild with QTC_STATIC=ON)");
        return 3;
#endif
    }
    if (rc != 0) {
        logLine(QString("QTC_HOST_INIT_FAILED reason=init rc=%1").arg(rc));
        return 3;
    }

    // qt_commander_init wrote "<port>\n<token>\n" before returning.
    QFile file(portFile);
    if (!file.open(QIODevice::ReadOnly | QIODevice::Text)) {
        logLine(QString("QTC_HOST_INIT_FAILED reason=port-file-missing path=%1")
                    .arg(portFile));
        return 3;
    }
    const int port = file.readLine().trimmed().toInt();

    logLine(QString("QTC_HOST_READY session=%1 link=%2 port=%3 port_file=%4 pid=%5")
                .arg(g_session, g_useDll ? "dll" : "static")
                .arg(port)
                .arg(portFile)
                .arg(QCoreApplication::applicationPid()));
    return 0;
}

} // namespace

int main(int argc, char* argv[])
{
    QApplication app(argc, argv);
    QApplication::setApplicationName("qtc-host");

    QCommandLineParser parser;
    parser.setApplicationDescription("qt-commander in-process host harness");
    parser.addHelpOption();
    parser.addOptions({
        {{"s", "session"}, "session name (<= 12 chars, default host)", "name", "host"},
        {{"l", "link"}, "how to reach qt_commander_init: static | dll", "mode", "static"},
        {{"p", "port-dir"}, "directory for the port file", "dir"},
        {{"d", "dll"}, "libqt-commander.dll path for --link dll (default: next to this exe)", "path"},
        {{"n", "no-show"}, "create the window but do not show it"},
    });
    parser.process(app);

    g_session = parser.value("session");
    g_portDir = parser.value("port-dir");
    if (g_portDir.isEmpty())
        g_portDir = QCoreApplication::applicationDirPath();
    const QString link = parser.value("link");
    if (link != "static" && link != "dll") {
        logLine(QString("QTC_HOST_INIT_FAILED reason=bad --link value=%1").arg(link));
        return 2;
    }
    g_useDll = (link == "dll");
    g_dllPath = parser.value("dll");
    if (g_dllPath.isEmpty())
        g_dllPath = QCoreApplication::applicationDirPath() + "/libqt-commander.dll";

    static QMainWindow* keepAlive = buildWindow();  // top-level: lives until exit
    if (!parser.isSet("no-show"))
        keepAlive->show();

    // Init only after the window is shown: the library dispatches onto the
    // GUI thread's event loop, and accept/auth needs an idle main thread.
    QTimer::singleShot(300, []() {
        const int rc = callInit();
        if (rc != 0)
            QApplication::exit(rc);
    });
    return app.exec();
}
