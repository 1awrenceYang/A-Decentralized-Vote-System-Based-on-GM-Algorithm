/********************************************************************************
** Form generated from reading UI file 'QDebugDemo.ui'
**
** Created by: Qt User Interface Compiler version 5.15.2
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_QDEBUGDEMO_H
#define UI_QDEBUGDEMO_H

#include <QtCore/QVariant>
#include <QtWidgets/QApplication>
#include <QtWidgets/QComboBox>
#include <QtWidgets/QGridLayout>
#include <QtWidgets/QGroupBox>
#include <QtWidgets/QHBoxLayout>
#include <QtWidgets/QLabel>
#include <QtWidgets/QMainWindow>
#include <QtWidgets/QMenuBar>
#include <QtWidgets/QPushButton>
#include <QtWidgets/QStatusBar>
#include <QtWidgets/QTextBrowser>
#include <QtWidgets/QToolBar>
#include <QtWidgets/QVBoxLayout>
#include <QtWidgets/QWidget>

QT_BEGIN_NAMESPACE

class Ui_QDebugDemoClass
{
public:
    QWidget *centralWidget;
    QGridLayout *gridLayout_2;
    QVBoxLayout *verticalLayout_2;
    QGroupBox *groupBox;
    QHBoxLayout *horizontalLayout;
    QLabel *label;
    QComboBox *comboBox;
    QPushButton *pushButtonStartPrinting;
    QPushButton *pushButtonStopPrinting;
    QPushButton *pushButtonPrintSingle;
    QTextBrowser *textBrowser;
    QMenuBar *menuBar;
    QToolBar *mainToolBar;
    QStatusBar *statusBar;

    void setupUi(QMainWindow *QDebugDemoClass)
    {
        if (QDebugDemoClass->objectName().isEmpty())
            QDebugDemoClass->setObjectName(QString::fromUtf8("QDebugDemoClass"));
        QDebugDemoClass->resize(678, 550);
        centralWidget = new QWidget(QDebugDemoClass);
        centralWidget->setObjectName(QString::fromUtf8("centralWidget"));
        gridLayout_2 = new QGridLayout(centralWidget);
        gridLayout_2->setSpacing(6);
        gridLayout_2->setContentsMargins(11, 11, 11, 11);
        gridLayout_2->setObjectName(QString::fromUtf8("gridLayout_2"));
        verticalLayout_2 = new QVBoxLayout();
        verticalLayout_2->setSpacing(6);
        verticalLayout_2->setObjectName(QString::fromUtf8("verticalLayout_2"));
        groupBox = new QGroupBox(centralWidget);
        groupBox->setObjectName(QString::fromUtf8("groupBox"));
        horizontalLayout = new QHBoxLayout(groupBox);
        horizontalLayout->setSpacing(6);
        horizontalLayout->setContentsMargins(11, 11, 11, 11);
        horizontalLayout->setObjectName(QString::fromUtf8("horizontalLayout"));
        label = new QLabel(groupBox);
        label->setObjectName(QString::fromUtf8("label"));
        QSizePolicy sizePolicy(QSizePolicy::Maximum, QSizePolicy::Preferred);
        sizePolicy.setHorizontalStretch(0);
        sizePolicy.setVerticalStretch(0);
        sizePolicy.setHeightForWidth(label->sizePolicy().hasHeightForWidth());
        label->setSizePolicy(sizePolicy);

        horizontalLayout->addWidget(label);

        comboBox = new QComboBox(groupBox);
        comboBox->setObjectName(QString::fromUtf8("comboBox"));

        horizontalLayout->addWidget(comboBox);

        pushButtonStartPrinting = new QPushButton(groupBox);
        pushButtonStartPrinting->setObjectName(QString::fromUtf8("pushButtonStartPrinting"));

        horizontalLayout->addWidget(pushButtonStartPrinting);

        pushButtonStopPrinting = new QPushButton(groupBox);
        pushButtonStopPrinting->setObjectName(QString::fromUtf8("pushButtonStopPrinting"));

        horizontalLayout->addWidget(pushButtonStopPrinting);

        pushButtonPrintSingle = new QPushButton(groupBox);
        pushButtonPrintSingle->setObjectName(QString::fromUtf8("pushButtonPrintSingle"));

        horizontalLayout->addWidget(pushButtonPrintSingle);


        verticalLayout_2->addWidget(groupBox);

        textBrowser = new QTextBrowser(centralWidget);
        textBrowser->setObjectName(QString::fromUtf8("textBrowser"));

        verticalLayout_2->addWidget(textBrowser);


        gridLayout_2->addLayout(verticalLayout_2, 0, 0, 1, 1);

        QDebugDemoClass->setCentralWidget(centralWidget);
        menuBar = new QMenuBar(QDebugDemoClass);
        menuBar->setObjectName(QString::fromUtf8("menuBar"));
        menuBar->setGeometry(QRect(0, 0, 678, 25));
        QDebugDemoClass->setMenuBar(menuBar);
        mainToolBar = new QToolBar(QDebugDemoClass);
        mainToolBar->setObjectName(QString::fromUtf8("mainToolBar"));
        QDebugDemoClass->addToolBar(Qt::TopToolBarArea, mainToolBar);
        statusBar = new QStatusBar(QDebugDemoClass);
        statusBar->setObjectName(QString::fromUtf8("statusBar"));
        QDebugDemoClass->setStatusBar(statusBar);

        retranslateUi(QDebugDemoClass);

        QMetaObject::connectSlotsByName(QDebugDemoClass);
    } // setupUi

    void retranslateUi(QMainWindow *QDebugDemoClass)
    {
        QDebugDemoClass->setWindowTitle(QCoreApplication::translate("QDebugDemoClass", "QDebugDemo", nullptr));
        groupBox->setTitle(QCoreApplication::translate("QDebugDemoClass", "\346\216\247\345\210\266", nullptr));
        label->setText(QCoreApplication::translate("QDebugDemoClass", "\344\277\241\346\201\257\347\272\247\345\210\253\357\274\232", nullptr));
        pushButtonStartPrinting->setText(QCoreApplication::translate("QDebugDemoClass", "\345\274\200\345\247\213", nullptr));
        pushButtonStopPrinting->setText(QCoreApplication::translate("QDebugDemoClass", "\345\201\234\346\255\242", nullptr));
        pushButtonPrintSingle->setText(QCoreApplication::translate("QDebugDemoClass", "\346\211\223\345\215\260\345\215\225\346\235\241", nullptr));
    } // retranslateUi

};

namespace Ui {
    class QDebugDemoClass: public Ui_QDebugDemoClass {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_QDEBUGDEMO_H
