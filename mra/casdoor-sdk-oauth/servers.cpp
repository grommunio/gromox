#include "servers.h"
#include "ui_servers.h"
#include "mainwindow.h"

servers::servers(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::servers)
{
    ui->setupUi(this);
}

servers::~servers()
{
    delete ui;
}

void servers::on_pushButton_clicked()
{
    QApplication::quit();
}

