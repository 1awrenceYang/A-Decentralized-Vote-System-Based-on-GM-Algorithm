#ifndef MSGHANDLERWAPPER_H
#define MSGHANDLERWAPPER_H
#include <QtCore/QObject>
#include <QtCore/QMetaType>
#include <QtCore/QMutex>
#include <QtCore/QMutexLocker>
#include <QtCore/QCoreApplication>
#include <QtMessageHandler>
class MessageHandlerWrapper :public QObject
{
	Q_OBJECT
public:
	//保证任何时候访问该静态函数，都会访问到同一对象
	static MessageHandlerWrapper* get_instance() {
		static QMutex mutex;
		if (!m_instance) {
			QMutexLocker locker(&mutex);
			if (!m_instance)
				m_instance = new MessageHandlerWrapper;
		}
		return m_instance;
	}

signals:
	void message(QtMsgType type, const QString& msg);
private:
	MessageHandlerWrapper()
		:QObject(qApp)
	{
		qRegisterMetaType<QtMsgType>("QtMsgType");
		//安装自定义消息处理函数
		qInstallMessageHandler(msgHandlerFunction);
	}
	static MessageHandlerWrapper* m_instance;
	static void msgHandlerFunction(QtMsgType type, const QMessageLogContext& context, const QString& msg)
	{
		Q_UNUSED(context)
			QMetaObject::invokeMethod(MessageHandlerWrapper::get_instance(), "message"
				, Q_ARG(QtMsgType, type)
				, Q_ARG(QString, msg));
	}
	~MessageHandlerWrapper() {
		static QMutex mutex;
		if (m_instance) {
			QMutexLocker locker(&mutex);
			if (m_instance) {
				delete m_instance;
			}
		}
	}
};
#endif // MSGHANDLERWAPPER

