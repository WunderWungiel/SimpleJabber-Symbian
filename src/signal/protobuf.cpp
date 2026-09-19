// SimpleJabber - an XMPP client with OMEMO for Symbian Belle.
// Copyright (C) 2026 Symnok - MIT License, see LICENSE.
#include "protobuf.h"

namespace Signal {

void ProtoWriter::putVarint(quint64 v)
{
    do {
        uchar b = uchar(v & 0x7f);
        v >>= 7;
        if (v) b |= 0x80;
        m_out.append(char(b));
    } while (v);
}

void ProtoWriter::varint(int field, quint64 value)
{
    putVarint(quint64(field) << 3);
    putVarint(value);
}

void ProtoWriter::bytes(int field, const QByteArray &data)
{
    putVarint((quint64(field) << 3) | 2);
    putVarint(quint64(data.size()));
    m_out.append(data);
}

ProtoReader::ProtoReader(const QByteArray &data)
    : m_ok(true)
{
    int p = 0;
    const int n = data.size();
    while (p < n) {
        quint64 tag = 0;
        int shift = 0;
        bool more = true;
        while (more) {
            if (p >= n || shift > 63) { m_ok = false; return; }
            uchar b = uchar(data.at(p++));
            tag |= quint64(b & 0x7f) << shift;
            shift += 7;
            more = (b & 0x80) != 0;
        }
        Field f;
        f.number = int(tag >> 3);
        f.wireType = int(tag & 7);
        f.value = 0;
        switch (f.wireType) {
        case 0: {
            shift = 0; more = true;
            while (more) {
                if (p >= n || shift > 63) { m_ok = false; return; }
                uchar b = uchar(data.at(p++));
                f.value |= quint64(b & 0x7f) << shift;
                shift += 7;
                more = (b & 0x80) != 0;
            }
            break;
        }
        case 1:
            if (p + 8 > n) { m_ok = false; return; }
            p += 8;
            break;
        case 2: {
            quint64 len = 0;
            shift = 0; more = true;
            while (more) {
                if (p >= n || shift > 63) { m_ok = false; return; }
                uchar b = uchar(data.at(p++));
                len |= quint64(b & 0x7f) << shift;
                shift += 7;
                more = (b & 0x80) != 0;
            }
            if (len > quint64(n - p)) { m_ok = false; return; }
            f.data = data.mid(p, int(len));
            p += int(len);
            break;
        }
        case 5:
            if (p + 4 > n) { m_ok = false; return; }
            p += 4;
            break;
        default:
            m_ok = false;
            return;
        }
        m_fields.append(f);
    }
}

bool ProtoReader::has(int field) const
{
    for (int i = 0; i < m_fields.size(); ++i)
        if (m_fields.at(i).number == field) return true;
    return false;
}

quint64 ProtoReader::varint(int field, quint64 fallback) const
{
    // Last occurrence wins, as protobuf specifies for repeated scalars.
    for (int i = m_fields.size() - 1; i >= 0; --i)
        if (m_fields.at(i).number == field && m_fields.at(i).wireType == 0) return m_fields.at(i).value;
    return fallback;
}

QByteArray ProtoReader::bytes(int field) const
{
    for (int i = m_fields.size() - 1; i >= 0; --i)
        if (m_fields.at(i).number == field && m_fields.at(i).wireType == 2) return m_fields.at(i).data;
    return QByteArray();
}

} // namespace Signal
