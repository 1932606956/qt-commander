// quickshot.cpp -- reveal-then-capture composite behind qt.quickShot.
//
// Reveal strategy (outermost blocker first, re-checking capturability after
// every activation because QWidget::isVisible() folds the whole ancestor
// chain -- fixing the outer container usually fixes the inner ones):
//   QDockWidget            -> toggleViewAction()->trigger()   (dock-action)
//   slot toggleView(bool)  -> QMetaObject::invokeMethod       (dock-slot;
//                             ADS CDockWidget declares it public Q_SLOTS)
//   QTabWidget page        -> setCurrentWidget(page)          (tab)
//   QStackedWidget page    -> setCurrentWidget(page)          (stack)
//   QToolBox item          -> setCurrentWidget(page)          (toolbox)
//   hidden top-level       -> show()+raise()                  (window-show)
//   other hidden widget    -> show()                           (widget-show)
//   hidden QQuickItem      -> setProperty("visible", true)     (qml-visible)
// Anything else is reported in unhandled[] and never touched.
#include "quickshot.h"
#include "screenshot.h"
#include "ui_scanner.h"
#include "../compat_qt.h"

#include <QAction>
#include <QCoreApplication>
#include <QDockWidget>
#include <QElapsedTimer>
#include <QEventLoop>
#include <QMetaObject>
#include <QStackedWidget>
#include <QTabWidget>
#include <QThread>
#include <QToolBox>
#include <QWidget>
#include <QWindow>
#ifdef QT_COMMANDER_WITH_QML
#include <QQuickItem>
#endif

namespace {

/// Does *node* expose the ADS-style open/close slot?  (QDockWidget itself
/// has no toggleView slot -- it drives an action instead -- so this only
/// matches docking classes like CDockWidget that declare it Q_SLOTS.)
bool hasToggleViewSlot(const QObject* node)
{
    return node->metaObject()->indexOfSlot(
               QByteArrayLiteral("toggleView(bool)")) >= 0;
}

/// Best-effort restore for one activated dock-like node.
void restoreDockLike(QObject* node, bool prevVisible, QJsonObject& r)
{
    if (auto* dw = qobject_cast<QDockWidget*>(node)) {
        if (QAction* a = dw->toggleViewAction()) {
            if (a->isChecked() != prevVisible)
                a->trigger();
            r[QStringLiteral("ok")] = true;
            return;
        }
    }
    if (hasToggleViewSlot(node)) {
        r[QStringLiteral("ok")] = QMetaObject::invokeMethod(
            node, "toggleView", Q_ARG(bool, prevVisible));
        return;
    }
    if (auto* w = qobject_cast<QWidget*>(node)) {
        w->setVisible(prevVisible);
        r[QStringLiteral("ok")] = true;
    }
}

} // namespace

// ============================================================================
// isCapturable
// ============================================================================
bool QuickShot::isCapturable(QObject* target)
{
    if (!target)
        return false;
    if (auto* w = qobject_cast<QWidget*>(target))
        return w->isVisible() && !w->size().isEmpty();
#ifdef QT_COMMANDER_WITH_QML
    if (auto* item = qobject_cast<QQuickItem*>(target))
        return UiScanner::isEffectivelyVisible(item)
               && item->width() > 0.0 && item->height() > 0.0;
#endif
    if (auto* win = qobject_cast<QWindow*>(target))
        return win->handle() != nullptr
               && win->width() > 0 && win->height() > 0;
    return false;
}

// ============================================================================
// chain / blockers
// ============================================================================
QVector<QObject*> QuickShot::visualChain(QObject* target)
{
    // chain[0] = target ... chain[last] = top-level.  getVisualParent walks
    // parentWidget() for widgets and parentItem() for QML items.
    QVector<QObject*> chain;
    for (QObject* p = target; p && chain.size() < 256;
         p = UiScanner::getVisualParent(p)) {
        chain.append(p);
    }
    return chain;
}

void QuickShot::collectBlockers(const QVector<QObject*>& chain,
                                QVector<RevealStep>* blockers,
                                QJsonArray* unhandled)
{
    // i >= 0: the TARGET ITSELF counts too.  A hidden top-level widget
    // (a closed ads::CDockWidget is one) has no ancestor on the chain that
    // blocks it -- it IS the blocker; skipping i == 0 left such targets
    // with an empty reveal ledger and "not capturable after reveal".
    for (int i = chain.size() - 1; i >= 0; --i) {
        QObject* node = chain.at(i);
        QObject* child = (i > 0) ? chain.at(i - 1) : nullptr;

        RevealStep step;
        step.node = node;
        step.child = child;

        if (qobject_cast<QDockWidget*>(node) || hasToggleViewSlot(node)) {
            // Exact path (action vs slot vs show) is decided at activation
            // time; collection only tags the family.
            step.how = QStringLiteral("dock");
            blockers->append(step);
            continue;
        }
        if (auto* tabs = qobject_cast<QTabWidget*>(node)) {
            // QTabWidget's immediate visual child is its PRIVATE
            // QStackedWidget, not the page -- resolve the page through the
            // chain via indexOf() (>= 0 only for real tab pages).
            QWidget* page = nullptr;
            for (int j = 0; j < i; ++j) {
                auto* x = qobject_cast<QWidget*>(chain.at(j));
                if (x && tabs->indexOf(x) >= 0) {
                    page = x;
                    break;
                }
            }
            if (page && tabs->currentWidget() != page) {
                step.child = page;
                step.how = QStringLiteral("tab");
                blockers->append(step);
            }
            continue;
        }
        if (auto* stack = qobject_cast<QStackedWidget*>(node)) {
            QWidget* page = nullptr;
            for (int j = 0; j < i; ++j) {
                auto* x = qobject_cast<QWidget*>(chain.at(j));
                if (x && stack->indexOf(x) >= 0) {
                    page = x;
                    break;
                }
            }
            if (page && stack->currentWidget() != page) {
                step.child = page;
                step.how = QStringLiteral("stack");
                blockers->append(step);
            }
            continue;
        }
        if (auto* box = qobject_cast<QToolBox*>(node)) {
            QWidget* page = nullptr;
            for (int j = 0; j < i; ++j) {
                auto* x = qobject_cast<QWidget*>(chain.at(j));
                if (x && box->indexOf(x) >= 0) {
                    page = x;
                    break;
                }
            }
            if (page && box->currentWidget() != page) {
                step.child = page;
                step.how = QStringLiteral("toolbox");
                blockers->append(step);
            }
            continue;
        }
        if (auto* w = qobject_cast<QWidget*>(node)) {
            if (w->isWindow()) {
                if (!w->isVisible()) {
                    step.how = QStringLiteral("window-show");
                    blockers->append(step);
                }
            } else if (w->isHidden()) {
                step.how = QStringLiteral("widget-show");
                blockers->append(step);
            }
            continue;
        }
#ifdef QT_COMMANDER_WITH_QML
        if (qobject_cast<QQuickItem*>(node)) {
            if (!node->property("visible").toBool()) {
                step.how = QStringLiteral("qml-visible");
                blockers->append(step);
            }
            continue;
        }
#endif
        QJsonObject u;
        u[QStringLiteral("class")] =
            QString::fromLatin1(node->metaObject()->className());
        u[QStringLiteral("objectName")] = node->objectName();
        u[QStringLiteral("reason")] =
            QStringLiteral("no reveal strategy for this type");
        unhandled->append(u);
    }
}

// ============================================================================
// activate / restore
// ============================================================================
bool QuickShot::activate(RevealStep* step)
{
    QObject* node = step->node.data();
    QObject* child = step->child.data();
    if (!node)
        return false;

    const QString how = step->how;

    if (how == QStringLiteral("dock")) {
        auto* w = qobject_cast<QWidget*>(node);
        if (w && w->isVisible())
            return false;   // already satisfied
        const bool prevVisible = false;   // w is not visible on this path
        if (auto* dw = qobject_cast<QDockWidget*>(node)) {
            if (QAction* a = dw->toggleViewAction()) {
                step->prev = a->isChecked();
                a->trigger();
                step->post = a->isChecked();
                step->how = QStringLiteral("dock-action");
                return true;
            }
            step->prev = prevVisible;
            dw->show();
            dw->raise();
            step->post = true;
            step->how = QStringLiteral("dock-show");
            return true;
        }
        // ADS CDockWidget: its toggleView(bool) slot is the exact code path
        // its own toggle action drives, so the docking manager stays
        // consistent (no raw-show state drift).
        if (QMetaObject::invokeMethod(node, "toggleView",
                                      Q_ARG(bool, true))) {
            step->prev = prevVisible;
            step->post = true;
            step->how = QStringLiteral("dock-slot");
            return true;
        }
        if (w) {
            step->prev = prevVisible;
            w->show();
            w->raise();
            step->post = true;
            step->how = QStringLiteral("widget-show");
            return true;
        }
        return false;
    }

    if (how == QStringLiteral("tab") || how == QStringLiteral("stack")
        || how == QStringLiteral("toolbox")) {
        auto* w = qobject_cast<QWidget*>(node);
        auto* page = qobject_cast<QWidget*>(child);
        if (!w || !page)
            return false;
        int prev = -1;
        int post = -1;
        if (auto* tabs = qobject_cast<QTabWidget*>(w)) {
            if (tabs->currentWidget() == page)
                return false;
            prev = tabs->currentIndex();
            tabs->setCurrentWidget(page);
            post = tabs->currentIndex();
        } else if (auto* stack = qobject_cast<QStackedWidget*>(w)) {
            if (stack->currentWidget() == page)
                return false;
            prev = stack->currentIndex();
            stack->setCurrentWidget(page);
            post = stack->currentIndex();
        } else if (auto* box = qobject_cast<QToolBox*>(w)) {
            if (box->currentWidget() == page)
                return false;
            prev = box->currentIndex();
            box->setCurrentWidget(page);
            post = box->currentIndex();
        } else {
            return false;
        }
        step->prev = prev;
        step->post = post;
        return true;
    }

    if (how == QStringLiteral("window-show")
        || how == QStringLiteral("widget-show")) {
        auto* w = qobject_cast<QWidget*>(node);
        if (!w || w->isVisible())
            return false;
        step->prev = false;
        w->show();
        if (how == QStringLiteral("window-show"))
            w->raise();
        step->post = true;
        return true;
    }

#ifdef QT_COMMANDER_WITH_QML
    if (how == QStringLiteral("qml-visible")) {
        if (!qobject_cast<QQuickItem*>(node))
            return false;
        if (node->property("visible").toBool())
            return false;
        step->prev = false;
        node->setProperty("visible", true);
        step->post = true;
        return true;
    }
#endif

    return false;
}

void QuickShot::restoreSteps(const QVector<RevealStep>& revealed,
                             QJsonArray* restored)
{
    for (int i = revealed.size() - 1; i >= 0; --i) {
        const RevealStep& step = revealed.at(i);
        QObject* node = step.node.data();
        QJsonObject r = stepToJson(step);
        r[QStringLiteral("ok")] = false;
        if (!node) {
            r[QStringLiteral("reason")] = QStringLiteral("object gone");
            restored->append(r);
            continue;
        }
        const QString how = step.how;
        if (how == QStringLiteral("dock-action")
            || how == QStringLiteral("dock-slot")
            || how == QStringLiteral("dock-show")) {
            restoreDockLike(node, step.prev.toBool(), r);
        } else if (how == QStringLiteral("tab")
                   || how == QStringLiteral("stack")
                   || how == QStringLiteral("toolbox")) {
            if (auto* w = qobject_cast<QWidget*>(node)) {
                const int idx = step.prev.toInt();
                bool ok = false;
                if (auto* tabs = qobject_cast<QTabWidget*>(w)) {
                    tabs->setCurrentIndex(idx); ok = true;
                } else if (auto* stack = qobject_cast<QStackedWidget*>(w)) {
                    stack->setCurrentIndex(idx); ok = true;
                } else if (auto* box = qobject_cast<QToolBox*>(w)) {
                    box->setCurrentIndex(idx); ok = true;
                }
                r[QStringLiteral("ok")] = ok;
            }
        } else if (how == QStringLiteral("window-show")
                   || how == QStringLiteral("widget-show")) {
            if (auto* w = qobject_cast<QWidget*>(node)) {
                w->setVisible(step.prev.toBool());
                r[QStringLiteral("ok")] = true;
            }
        }
#ifdef QT_COMMANDER_WITH_QML
        else if (how == QStringLiteral("qml-visible")) {
            r[QStringLiteral("ok")] =
                node->setProperty("visible", step.prev);
        }
#endif
        restored->append(r);
    }
}

// ============================================================================
// serialization / run
// ============================================================================
QJsonObject QuickShot::stepToJson(const RevealStep& step)
{
    QJsonObject o;
    if (step.node) {
        o[QStringLiteral("class")] =
            QString::fromLatin1(step.node->metaObject()->className());
        o[QStringLiteral("objectName")] = step.node->objectName();
    }
    o[QStringLiteral("how")] = step.how;
    if (step.prev.isValid())
        o[QStringLiteral("prev")] = step.prev.toJsonValue();
    if (step.post.isValid())
        o[QStringLiteral("post")] = step.post.toJsonValue();
    return o;
}

QuickShotOutcome QuickShot::run(QObject* target, const QString& dir, int seq,
                                bool reveal, bool restore, int timeoutMs)
{
    QuickShotOutcome out;

    // Bounded wait that keeps the GUI thread servicing events (layouts,
    // ADS async show, first paint) until the target is capturable.
    auto waitUntilCapturable = [target, timeoutMs]() {
        QElapsedTimer t;
        t.start();
        while (!isCapturable(target)) {
            if (t.hasExpired(timeoutMs))
                return false;
            QCoreApplication::processEvents(QEventLoop::AllEvents, 50);
            QThread::msleep(10);
        }
        return true;
    };

    if (!isCapturable(target)) {
        if (!reveal) {
            out.message = QStringLiteral(
                "Element is not visible (or has zero size); "
                "pass reveal=true to auto-reveal it");
            return out;
        }
        const QVector<QObject*> chain = visualChain(target);
        QVector<RevealStep> blockers;
        collectBlockers(chain, &blockers, &out.unhandled);
        for (RevealStep& s : blockers) {
            if (activate(&s))
                out.revealed.append(s);
            if (waitUntilCapturable())
                break;
        }
        if (!isCapturable(target)) {
            out.message = QStringLiteral("not capturable after reveal");
            return out;
        }
    }

    const QString path = Screenshot::capture(target, dir, seq);
    if (path.isEmpty()) {
        out.message = QStringLiteral("screenshot failed");
        return out;
    }
    out.ok = true;
    out.path = path;
    if (restore && !out.revealed.isEmpty())
        restoreSteps(out.revealed, &out.restored);
    return out;
}
