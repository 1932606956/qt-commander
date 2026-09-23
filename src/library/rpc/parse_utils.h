#pragma once
#include <QJsonObject>
#include <cmath>
#include <cstdint>

/// Parse element ID from JSON params.
///
/// Accepts both camelCase (``elementId``) and snake_case (``element_id``),
/// as well as direct integer values.
///
/// Returns true and sets *outId* on success; returns false otherwise.
inline bool qt_parse_element_id(const QJsonObject& params, uint64_t& outId) {
    QJsonValue val = params.value(QStringLiteral("elementId"));
    if (val.isUndefined())
        val = params.value(QStringLiteral("element_id"));
    if (val.isUndefined())
        return false;
    if (val.isDouble()) {
        // JSON numbers arrive as double: casting a negative, NaN, non-integral
        // or out-of-range value to uint64_t is undefined behaviour and could
        // yield a huge id that is then treated as valid.  Values above 2^53 are
        // rejected because integers are no longer exactly representable there.
        const double idNum = val.toDouble();
        if (!std::isfinite(idNum) || idNum < 0.0 ||
            idNum > 9007199254740992.0 || std::floor(idNum) != idNum) {
            return false;   // invalid input: report "no id" like a missing param
        }
        outId = static_cast<uint64_t>(idNum);
        return outId > 0;
    }
    const QString idStr = val.toString();
    if (idStr.isEmpty())
        return false;
    bool ok = false;
    outId = idStr.toULongLong(&ok);
    return ok;
}
