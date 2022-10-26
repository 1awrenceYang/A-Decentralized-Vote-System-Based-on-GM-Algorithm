#pragma once

#include <QtWidgets/QMainWindow>
#include "ui_QDebugDemo.h"
#include "MessageHandlerWrapper.h"
#include <thread>

class QDebugDemo : public QMainWindow
{
    Q_OBJECT

public:
    QDebugDemo(QWidget *parent = nullptr);
    ~QDebugDemo();
    void onStartPrinting();
    void onStopPrinting();
    void onPrintingSingleMsg();
    void VoteTest();
    void PrintQtMessage(char* Message, int Length);//输入不需要补0
private:
    Ui::QDebugDemoClass ui;
    void logToUI(QtMsgType type, QString msg);
    std::thread* printingThread;
    bool aboutToExit;
    bool paused;
    MessageHandlerWrapper* messageHandler;
};
