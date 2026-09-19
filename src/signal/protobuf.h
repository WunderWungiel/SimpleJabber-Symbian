// SimpleJabber - an XMPP client with OMEMO for Symbian Belle.
// Copyright (C) 2026 Symnok - MIT License, see LICENSE.
//
// The sliver of protocol buffers the Signal wire format needs: varint and
// length-delimited fields, written in field order and read by field number. Only
// SignalMessage and PreKeySignalMessage are ever encoded (session state is stored in the
// app's own format), so there is no schema machinery, just two small helpers.
#ifndef SJ_PROTOBUF_H
#define SJ_PROTOBUF_H

#include <QByteArray>
#include <QList>
#include <QPair>

namespace Signal {

class ProtoWriter
{
public:
    void varint(int field, quint64 value);
    void bytes(int field, const QByteArray &data);
    const QByteArray &result() const { return m_out; }

private:
    void putVarint(quint64 v);
    QByteArray m_out;
};

class ProtoReader
{
public:
    /// Parses the message; ok() is false on malformed input.
    explicit ProtoReader(const QByteArray &data);
    bool ok() const { return m_ok; }

    bool has(int field) const;
    quint64 varint(int field, quint64 fallback = 0) const;
    QByteArray bytes(int field) const;

private:
    struct Field { int number; int wireType; quint64 value; QByteArray data; };
    QList<Field> m_fields;
    bool m_ok;
};

} // namespace Signal

#endif
