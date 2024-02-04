#ifndef CONTROLLER_H
#define CONTROLLER_H

#define SERVICE_VERSION     "1.0.3"
#define RECONNECT_TIMEOUT   10000

#include <QTcpSocket>
#include <QTimer>
#include "crypto.h"
#include "homed.h"

struct handshakeRequest
{
    quint32 prime;
    quint32 generator;
    quint32 sharedKey;
};

class Controller : public HOMEd
{
    Q_OBJECT

public:

    Controller(const QString &configFile);

private:

    QTcpSocket *m_socket;
    QTimer *m_timer;
    AES128 *m_aes;
    DH *m_dh;

    QString m_uniqueId, m_token, m_host;
    quint16 m_port;
    bool m_handshake;

    QByteArray m_buffer;
    
    QList <QString> m_retained, m_topics;
    QMap <QString, QJsonObject> m_messages;

    void parseData(QByteArray &buffer);
    void sendData(const QByteArray &data);
    void sendMessage(const QString &topic, const QJsonObject &message);

public slots:

    void quit(void) override;

private slots:

    void mqttConnected(void) override;
    void mqttReceived(const QByteArray &message, const QMqttTopicName &topic) override;

    void connected(void);
    void disconnected(void);
    void errorOccurred(QAbstractSocket::SocketError error);
    void readyRead(void);

    void connectToHost(void);

};

#endif
