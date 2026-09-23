#include "element_map.h"

// ======================== Convenience methods =========================

void ElementMap::clear()
{
    QWriteLocker locker(&lock_);
    // No per-object disconnect is needed: Qt breaks all connections of a
    // QObject when it is destroyed, and there are no tracking connections
    // to tear down for live objects (QPointer handles dead ones).
    map_.clear();
    revMap_.clear();
    next_id_ = 1;
    // epoch_ is deliberately NOT reset: it is a monotonic generation
    // counter (each snapshot rebuild calls incrementEpoch()), so callers
    // can distinguish "which renumber generation an id belongs to".
}

uint64_t ElementMap::insertIfAbsent(QObject* obj)
{
    if (!obj)
        return 0;
    QWriteLocker locker(&lock_);
    const QPointer<QObject> ptr(obj);
    const auto it = revMap_.constFind(ptr);
    if (it != revMap_.constEnd())
        return it.value();
    const uint64_t id = next_id_++;
    map_.insert(id, ptr);
    revMap_.insert(ptr, id);
    return id;
}

void ElementMap::insert(uint64_t id, QObject* obj)
{
    QWriteLocker locker(&lock_);
    // Track via QPointer: it auto-nulls when the object dies (Qt's weak-ref
    // machinery, no callback), so stale ids resolve to nullptr instead of
    // dangling.  No destroyed() connection is used -- the old tracking
    // either never delivered (cross-thread queued connection) or re-entered
    // the map lock from ~QObject (direct-connection deadlock).
    const QPointer<QObject> ptr(obj);

    // Overwriting an id with a DIFFERENT object must drop the displaced
    // object's reverse entry.  Otherwise revMap_ keeps two objects pointing
    // at the same id: idFor(displaced) still reports the id, and the next
    // insertIfAbsent(displaced) would hand that id straight back even though
    // the map now resolves it to somebody else.  Only remove it when the
    // reverse entry really points at *this* id -- the same object may
    // legitimately be mapped under several ids.
    const QPointer<QObject> previous = map_.value(id);
    if (!previous.isNull() && previous != ptr) {
        const auto revIt = revMap_.constFind(previous);
        if (revIt != revMap_.constEnd() && revIt.value() == id)
            revMap_.remove(previous);
    }

    map_.insert(id, ptr);
    revMap_.insert(ptr, id);

    // Keep next_id_ strictly above every id ever stored here.  The snapshot
    // handler assigns ids 1..N from its own local counter, so without this
    // next_id_ is still 1 afterwards and the next grow-only insertIfAbsent
    // re-issues id 1: map_.insert() then silently replaces the object that
    // owned it while revMap_ keeps both objects pointing at id 1.
    if (id >= next_id_)
        next_id_ = id + 1;
}

QObject* ElementMap::lookup(uint64_t id) const
{
    QReadLocker locker(&lock_);
    return map_.value(id).data();
}

uint64_t ElementMap::idFor(QObject* obj) const
{
    QReadLocker locker(&lock_);
    return revMap_.value(QPointer<QObject>(obj), 0);
}

uint64_t ElementMap::epoch() const
{
    QReadLocker locker(&lock_);
    return epoch_;
}

uint64_t ElementMap::nextId() const
{
    QReadLocker locker(&lock_);
    return next_id_;
}

void ElementMap::incrementEpoch()
{
    QWriteLocker locker(&lock_);
    epoch_++;
}

// ======================== External lock/unlock =========================
//
// These methods are used when a caller needs to hold the lock across
// multiple operations without releasing in between.
//
// Typical snapshot sequence on the main thread:
//   map.lockForWrite();
//   map.clear();                       // clears + resets next_id (not epoch)
//   map_ = rebuild(...);               // external rebuild
//   map.incrementEpoch();              // new renumber generation
//   map.unlock();
//
// Typical worker-thread sequence:
//   map.lockForRead();
//   QObject* obj = map.lookup(id);
//   if (obj) { /* read properties */ }
//   map.unlockRead();

void ElementMap::lockForWrite()
{
    lock_.lockForWrite();
}

void ElementMap::unlock()
{
    lock_.unlock();
}

void ElementMap::lockForRead() const
{
    lock_.lockForRead();
}

void ElementMap::unlockRead() const
{
    lock_.unlock();
}
