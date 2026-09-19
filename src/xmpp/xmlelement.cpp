// SimpleJabber - an XMPP client with OMEMO for Symbian Belle.
// Copyright (C) 2026 Symnok - MIT License, see LICENSE.
#include "xmlelement.h"

QString XmlElement::attribute(const QString &name) const
{
    for (int i = 0; i < m_attributes.size(); ++i)
        if (m_attributes.at(i).first == name) return m_attributes.at(i).second;
    return QString();
}

bool XmlElement::hasAttribute(const QString &name) const
{
    for (int i = 0; i < m_attributes.size(); ++i)
        if (m_attributes.at(i).first == name) return true;
    return false;
}

XmlElement &XmlElement::setAttribute(const QString &name, const QString &value)
{
    for (int i = 0; i < m_attributes.size(); ++i)
        if (m_attributes.at(i).first == name) { m_attributes[i].second = value; return *this; }
    m_attributes.append(qMakePair(name, value));
    return *this;
}

XmlElement &XmlElement::addChild(const XmlElement &child)
{
    m_children.append(child);
    return *this;
}

XmlElement XmlElement::child(const QString &ns, const QString &name) const
{
    for (int i = 0; i < m_children.size(); ++i)
        if (m_children.at(i).is(ns, name)) return m_children.at(i);
    return XmlElement();
}

QList<XmlElement> XmlElement::childrenNamed(const QString &ns, const QString &name) const
{
    QList<XmlElement> out;
    for (int i = 0; i < m_children.size(); ++i)
        if (m_children.at(i).is(ns, name)) out.append(m_children.at(i));
    return out;
}

XmlElement XmlElement::findDescendant(const QString &ns, const QString &name) const
{
    for (int i = 0; i < m_children.size(); ++i) {
        if (m_children.at(i).is(ns, name)) return m_children.at(i);
        const XmlElement deeper = m_children.at(i).findDescendant(ns, name);
        if (!deeper.isNull()) return deeper;
    }
    return XmlElement();
}

QString XmlElement::escape(const QString &s)
{
    QString out;
    out.reserve(s.size() + 8);
    for (int i = 0; i < s.size(); ++i) {
        const QChar c = s.at(i);
        switch (c.unicode()) {
        case '&': out += QLatin1String("&amp;"); break;
        case '<': out += QLatin1String("&lt;"); break;
        case '>': out += QLatin1String("&gt;"); break;
        case '"': out += QLatin1String("&quot;"); break;
        case '\'': out += QLatin1String("&apos;"); break;
        default:
            // XML 1.0 forbids most control characters; drop them rather than break the stream.
            if (c.unicode() < 0x20 && c != QLatin1Char('\n') && c != QLatin1Char('\r') && c != QLatin1Char('\t')) break;
            out += c;
        }
    }
    return out;
}

void XmlElement::write(QString &out, const QString &parentNs) const
{
    out += QLatin1Char('<');
    out += m_name;
    if (!m_ns.isEmpty() && m_ns != parentNs) {
        out += QLatin1String(" xmlns='");
        out += escape(m_ns);
        out += QLatin1Char('\'');
    }
    for (int i = 0; i < m_attributes.size(); ++i) {
        out += QLatin1Char(' ');
        out += m_attributes.at(i).first;
        out += QLatin1String("='");
        out += escape(m_attributes.at(i).second);
        out += QLatin1Char('\'');
    }
    if (m_text.isEmpty() && m_children.isEmpty()) {
        out += QLatin1String("/>");
        return;
    }
    out += QLatin1Char('>');
    out += escape(m_text);
    const QString myNs = m_ns.isEmpty() ? parentNs : m_ns;
    for (int i = 0; i < m_children.size(); ++i) m_children.at(i).write(out, myNs);
    out += QLatin1String("</");
    out += m_name;
    out += QLatin1Char('>');
}

QString XmlElement::toXml(const QString &parentNs) const
{
    QString out;
    write(out, parentNs);
    return out;
}
