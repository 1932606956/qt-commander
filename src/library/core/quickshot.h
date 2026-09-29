#pragma once
#include <QObject>
#include <QPointer>
#include <QJsonArray>
#include <QJsonObject>
#include <QString>
#include <QVariant>
#include <QVector>

/// One UI state change issued by the reveal pass.
struct RevealStep {
    QPointer<QObject> node;    // activated container (auto-nulls on destruction)
    QPointer<QObject> child;   // tab-like containers: the page on the chain
    QString how;               // dock-action | dock-slot | dock-show | tab |
                               // stack | toolbox | window-show | widget-show |
                               // qml-visible
    QVariant prev;             // state before activation (int index / bool)
    QVariant post;             // state right after activation
};

struct QuickShotOutcome {
    bool ok = false;
    QString path;              // PNG path on success
    QString message;           // failure reason when !ok
    QVector<RevealStep> revealed;
    QJsonArray restored;       // restore ledger (restore=true only)
    QJsonArray unhandled;      // blockers without a reveal strategy
};

/// quickShot: decide capturability, reveal blocking containers, capture.
///
/// "Capturable" means the offscreen grab path can render the target:
/// visibility chain + non-zero size.  Occlusion / z-order do NOT matter
/// (QWidget::grab re-renders; QWindow grabs the native surface).
///
/// Everything runs on the GUI thread inside one RPC dispatch.  The caller
/// must have released the ElementMap read lock: the post-activation wait
/// re-enters the event loop, exactly like the QML grabToImage path.
class QuickShot {
public:
    static bool isCapturable(QObject* target);

    static QuickShotOutcome run(QObject* target, const QString& dir, int seq,
                                bool reveal, bool restore, int timeoutMs);

    static QJsonObject stepToJson(const RevealStep& step);

private:
    static QVector<QObject*> visualChain(QObject* target);
    static void collectBlockers(const QVector<QObject*>& chain,
                                QVector<RevealStep>* blockers,
                                QJsonArray* unhandled);
    static bool activate(RevealStep* step);
    static void restoreSteps(const QVector<RevealStep>& revealed,
                             QJsonArray* restored);
};
