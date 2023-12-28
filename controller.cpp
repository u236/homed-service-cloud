#include <QtEndian>
#include <QCryptographicHash>
#include "controller.h"
#include "logger.h"

Controller::Controller(const QString &configFile) : HOMEd(configFile), m_socket(new QTcpSocket(this)), m_timer(new QTimer(this)), m_aes(new AES128), m_dh(new DH), m_handshake(false)
{
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

void Controller::parseData(void)
{
    QJsonObject json;
    QString action, topic;

    m_aes->cbcDecrypt(m_buffer);

    json = QJsonDocument::fromJson(m_buffer.constData()).object();
    action = json.value("action").toString();
    topic = json.value("topic").toString();

    if (action == "subscribe")
    {
        if (!m_topics.contains(topic))
            m_topics.append(topic);

        if (m_messages.contains(topic))
        {
            sendMessage(topic, m_messages.value(topic));
            return;
        }

        mqttSubscribe(mqttTopic(topic));
    }
    else if (action == "publish")
        mqttPublish(mqttTopic(topic), json.value("message").toObject());
    else if (action == "unsubscribe")
        m_topics.removeAll(topic);
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
    logInfo << "MQTT connected";

    for (int i = 0; i < m_topics.count(); i++)
        mqttSubscribe(mqttTopic(m_topics.at(i)));
}

void Controller::mqttReceived(const QByteArray &message, const QMqttTopicName &topic)
{
    QString subTopic = topic.name().replace(mqttTopic(), QString());
    QJsonObject json = QJsonDocument::fromJson(message).object();

    if (m_retained.contains(subTopic.split('/').value(0)))
        m_messages.insert(subTopic, json);

    if (m_handshake && m_topics.contains(subTopic))
    {
        sendMessage(subTopic, json);
        return;
    }

    mqttUnsubscribe(topic.name());
    m_messages.remove(subTopic);
}

void Controller::connected(void)
{
    handshakeRequest data;

    logInfo << "Connected to server";

    data.prime = qToBigEndian(m_dh->prime());
    data.generator = qToBigEndian(m_dh->generator());
    data.sharedKey = qToBigEndian(m_dh->sharedKey());

    m_socket->write(QByteArray(reinterpret_cast <char*> (&data), sizeof(data)));
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
    QByteArray buffer = m_socket->readAll();

    if (!m_handshake)
    {
        QByteArray hash;
        quint32 value, key;

        memcpy(&value, buffer.constData(), sizeof(value));
        key = m_dh->privateKey(qFromBigEndian(value));
        hash = QCryptographicHash::hash(QByteArray(reinterpret_cast <char*> (&key), sizeof(key)), QCryptographicHash::Md5);

        m_aes->init(hash, QCryptographicHash::hash(hash, QCryptographicHash::Md5));
        sendData(QJsonDocument({{"uniqueId", m_uniqueId}, {"token", m_token}}).toJson(QJsonDocument::Compact));

        m_handshake = true;
    }
    else
    {
        for (int i = 0; i < buffer.length(); i++)
        {
            switch (buffer.at(i))
            {
                case 0x42: m_buffer.clear(); break;
                case 0x43: parseData(); break;

                case 0x44:

                    switch (buffer.at(++i))
                    {
                        case 0x62: m_buffer.append(0x42); break;
                        case 0x63: m_buffer.append(0x43); break;
                        case 0x64: m_buffer.append(0x44); break;
                    }

                    break;

                default: m_buffer.append(buffer.at(i)); break;
            }
        }
    }
}

void Controller::connectToHost(void)
{
    m_socket->connectToHost(m_host, m_port);
}
