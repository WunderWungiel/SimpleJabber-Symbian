// SimpleJabber - an XMPP client with OMEMO for Symbian Belle.
// Copyright (C) 2026 Symnok - MIT License, see LICENSE.
//
// A small namespace-aware XML element used for every stanza in both directions. Incoming
// elements are built from QXmlStreamReader tokens (which resolves namespaces); outgoing
// ones are serialised with xmlns declarations wherever the namespace changes from the
// parent's, which is all XMPP needs.
#ifndef SJ_XMLELEMENT_H
#define SJ_XMLELEMENT_H

#include <QList>
#include <QPair>
#include <QString>
#include <QStringList>

class XmlElement
{
public:
    XmlElement() {}
    XmlElement(const QString &ns, const QString &name) : m_ns(ns), m_name(name) {}
    XmlElement(const QString &ns, const QString &name, const QString &text) : m_ns(ns), m_name(name), m_text(text) {}

    bool isNull() const { return m_name.isEmpty(); }
    QString ns() const { return m_ns; }
    QString name() const { return m_name; }
    bool is(const QString &ns, const QString &name) const { return m_ns == ns && m_name == name; }

    QString attribute(const QString &name) const;
    bool hasAttribute(const QString &name) const;
    XmlElement &setAttribute(const QString &name, const QString &value);

    /// Direct character data of this element (children's text excluded).
    QString text() const { return m_text; }
    void setText(const QString &t) { m_text = t; }
    void appendText(const QString &t) { m_text += t; }

    const QList<XmlElement> &children() const { return m_children; }
    XmlElement &addChild(const XmlElement &child);
    /// First child with this namespace and name, or a null element.
    XmlElement child(const QString &ns, const QString &name) const;
    /// All children with this namespace and name.
    QList<XmlElement> childrenNamed(const QString &ns, const QString &name) const;
    /// Depth-first search for the first descendant with this namespace and name.
    XmlElement findDescendant(const QString &ns, const QString &name) const;

    /// Serialised with the namespace declared where it differs from parentNs.
    QString toXml(const QString &parentNs = QString()) const;

    static QString escape(const QString &s);

private:
    void write(QString &out, const QString &parentNs) const;

    QString m_ns;
    QString m_name;
    QList<QPair<QString, QString> > m_attributes;
    QString m_text;
    QList<XmlElement> m_children;
};

#endif
