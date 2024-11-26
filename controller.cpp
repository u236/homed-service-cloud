#include <QtEndian>
#include <QCryptographicHash>
#include "controller.h"
#include "logger.h"

Controller::Controller(const QString &configFile) : HOMEd(configFile), m_socket(new QTcpSocket(this)), m_timer(new QTimer(this)), m_aes(new AES128), m_handshake(false)
{
    logInfo << "Starting version" << SERVICE_VERSION;
    logInfo << "Configuration file is" << getConfig()->fileName();

    m_retained = {"device", "expose", "service", "status"}; // TODO: check this

    connect(m_socket, &QTcpSocket::connected, this, &Controller::connected);
    connect(m_socket, &QTcpSocket::disconnected, this, &Controller::disconnected);
    connect(m_socket, &QTcpSocket::readyRead, this, &Controller::readyRead);
    connect(m_socket, &QTcpSocket::errorOccurred, this, &Controller::errorOccurred);
    connect(m_timer, &QTimer::timeout, this, &Controller::connectToHost);

    m_uniqueId = getConfig()->value("cloud/uniqueid").toString();
    m_token = getConfig()->value("cloud/token").toString();
    m_host = getConfig()->value("cloud/host", "cloud.homed.dev").toString();
    m_port = static_cast <quint16> (getConfig()->value("cloud/port", 8042).toInt());

    if (m_uniqueId.isEmpty() || m_token.isEmpty())
    {
        logWarning << "Unique ID or Token is empty, connection aborted";
        return;
    }

    m_timer->setSingleShot(true);
    connectToHost();
}

void Controller::parseData(QByteArray &buffer)
{
    QJsonObject json;
    QString action, topic;

    m_aes->cbcDecrypt(buffer);

    json = QJsonDocument::fromJson(buffer.constData()).object();
    action = json.value("action").toString();
    topic = json.value("topic").toString();

    if (action == "subscribe")
    {
        if (!m_topics.contains(topic))
            m_topics.append(topic);

        for (auto it = m_messages.begin(); it != m_messages.end(); it++)
        {
            if (topic.endsWith('#') ? !it.key().startsWith(topic.mid(0, topic.indexOf("#"))) : it.key() != topic)
                continue;

            sendMessage(it.key(), QJsonDocument::fromJson(it.value()).object());
        }

        mqttSubscribe(mqttTopic(topic));
    }
    else if (action == "publish")
        mqttPublish(mqttTopic(topic), json.value("message").toObject());
}

void Controller::sendData(const QByteArray &data)
{
    QByteArray buffer = data, packet = QByteArray(1, 0x42);

    if (buffer.length() % 16)
        buffer.append(16 - buffer.length() % 16, 0);

    m_aes->cbcEncrypt(buffer);

    for (int i = 0; i < buffer.length(); i++)
    {
        switch (buffer.at(i))
        {
            case 0x42: packet.append(0x44).append(0x62); break;
            case 0x43: packet.append(0x44).append(0x63); break;
            case 0x44: packet.append(0x44).append(0x64); break;
            default:   packet.append(buffer.at(i)); break;
        }
    }

    m_socket->write(packet.append(0x43));
}

void Controller::sendMessage(const QString &topic, const QJsonObject &message)
{
    QJsonObject json = {{"topic", topic}};

    if (!message.isEmpty())
        json.insert("message", message);

    sendData(QJsonDocument(json).toJson(QJsonDocument::Compact));
}

void Controller::quit(void)
{
    delete m_aes;
    delete m_dh;
    HOMEd::quit();
}

void Controller::mqttConnected(void)
{
    for (int i = 0; i < m_topics.count(); i++)
        mqttSubscribe(mqttTopic(m_topics.at(i)));

    mqttPublishStatus();
}

void Controller::mqttReceived(const QByteArray &message, const QMqttTopicName &topic)
{
    QString subTopic = topic.name().replace(mqttTopic(), QString());

    if (m_retained.contains(subTopic.split('/').value(0)))
        m_messages.insert(subTopic, message);

    if (!m_handshake)
        return;

    for (int i = 0; i < m_topics.count(); i++)
    {
        const QString item = m_topics.at(i);

        if (item.endsWith('#') ? !subTopic.startsWith(item.mid(0, item.indexOf("#"))) : subTopic != item)
            continue;

        sendMessage(subTopic, QJsonDocument::fromJson(message).object());
        break;
    }
}

void Controller::connected(void)
{
    handshakeRequest handshake;

    if (m_dh)
        delete m_dh;

    logInfo << "Connected to server";
    m_dh = new DH;

    handshake.prime = qToBigEndian(m_dh->prime());
    handshake.generator = qToBigEndian(m_dh->generator());
    handshake.sharedKey = qToBigEndian(m_dh->sharedKey());

    m_socket->write(QByteArray(reinterpret_cast <char*> (&handshake), sizeof(handshake)));
}

void Controller::disconnected(void)
{
    logInfo << "Disconnected from server";
    m_timer->start(RECONNECT_TIMEOUT);
    m_handshake = false;
}

void Controller::errorOccurred(QAbstractSocket::SocketError error)
{
    logWarning << "Server connection error:" << error;
    m_timer->start(RECONNECT_TIMEOUT);
    m_handshake = false;
}

void Controller::readyRead(void)
{
    QByteArray data = m_socket->readAll();

    if (!m_handshake)
    {
        QByteArray hash;
        quint32 value, key;

        memcpy(&value, data.constData(), sizeof(value));
        key = qToBigEndian(m_dh->privateKey(qFromBigEndian(value)));
        hash = QCryptographicHash::hash(QByteArray(reinterpret_cast <char*> (&key), sizeof(key)), QCryptographicHash::Md5);

        m_aes->init(hash, QCryptographicHash::hash(hash, QCryptographicHash::Md5));
        sendData(QJsonDocument({{"uniqueId", m_uniqueId}, {"token", m_token}}).toJson(QJsonDocument::Compact));

        m_handshake = true;
    }
    else
    {
        QByteArray buffer;
        int length;

        m_buffer.append(data); // TODO: check for overflow

        while((length = m_buffer.indexOf(0x43)) > 0)
        {
            for (int i = 0; i < length; i++)
            {
                switch (m_buffer.at(i))
                {
                    case 0x42: buffer.clear(); break;
                    case 0x44: buffer.append(m_buffer.at(++i) & 0xDF); break;
                    default:   buffer.append(m_buffer.at(i)); break;
                }
            }

            m_buffer.remove(0, length + 1);
            parseData(buffer);
        }
    }
}

void Controller::connectToHost(void)
{
    m_socket->connectToHost(m_host, m_port);
}
