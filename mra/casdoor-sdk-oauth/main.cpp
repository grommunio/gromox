#include "mainwindow.h"
#include <QApplication>

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    MainWindow w;
    w.setWindowTitle("Casdoor OAuth");
    w.setWindowIcon(QIcon(":/assert/favicon.png"));
    w.show();

    return a.exec();
}
