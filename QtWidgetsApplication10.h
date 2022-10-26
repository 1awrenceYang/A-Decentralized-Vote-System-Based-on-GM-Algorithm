#pragma once

#include <QtWidgets/QMainWindow>
#include "ui_QtWidgetsApplication10.h"

class QtWidgetsApplication10 : public QMainWindow
{
    Q_OBJECT

public:
    QtWidgetsApplication10(QWidget *parent = nullptr);
    ~QtWidgetsApplication10();

private:
    Ui::QtWidgetsApplication10Class ui;
};
