#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QWebEngineView>
#include <QtNetWork>
#include <QTableView>
#include <QHeaderView>
#include <QStandardItemModel>
#include "servers.h"

#include "casdoor_config.h"
#include "jwt-cpp/jwt.h"


namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

    std::string endpoint = "http://localhost:8000";
    std::string client_id = "4a4ee573e317efa7f4e9";
    std::string client_secret = "c9165baf40d9fc6ea14172417b2e2ffaf64b4994";
    std::string certificate = R"(-----BEGIN CERTIFICATE-----
MIIE2TCCAsGgAwIBAgIDAeJAMA0GCSqGSIb3DQEBCwUAMCYxDjAMBgNVBAoTBWFk
bWluMRQwEgYDVQQDDAtjZXJ0X2NrZmY3azAeFw0yMjEyMjUxNTQyNDRaFw00MjEy
MjUxNTQyNDRaMCYxDjAMBgNVBAoTBWFkbWluMRQwEgYDVQQDDAtjZXJ0X2NrZmY3
azCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAJxjhd6lWo0C2CLBUnZH
TPjt2NCfqmnKPqwkbqO8FdndGRWPrqeR/P8Y6D/y1RLeVvNA+5qkSNPIZGS05dEV
fiSNXUq9IeMXiBnt91BSalLKPciHOthLWacuShnakiZ1xf1TZjLEzaCIrgFybQa9
JDv8l17e4I/r+SEtYkvNnRUzN3zukraLo07fG0YToYbZOLxQTwFreSLxgsjMM526
QFfhhMfNnu6ukBxHUuKadclagyiE4V8EZZR8YydmJ/ZPiz7114K1r8yEKZpYHLz8
ra9boqkrWTuxCXTFM8ELqT5Q26hH+V1ooLPHIrIxZFNXigmGXd1IyEm2OVIQ0E+N
mN3wKiys0uZak1CbKvYO3nSb8QD9MkC22BOSh1DWDcm24uGuX8GMNkcyyT4dU6YB
PDb/XBrVnbx8p/ifqZzjwBbjKH75Dd+x3ieSmVF5uQuHhrgEaRIqtbTf2u8y1rgs
U2f4hrvBjHs/O5nuMWwlpmX8/KAz2QIphZh035Oa04rE2X12dd8mB2/th6BlvPF4
E94W2HyLD0P/5TzYXwHGZsk0K5xpOpGesHOcJsv3A62sRnF0SMJWrJb1UP3rused
lahcBYOUUOb+N+Zh3Hzxz3RjhpD3aFfvsp4r6pHVAILuMra3sNA/hwNnN5aSYHT1
y0JK9PaXBWS0ouFKqGp0KjSZAgMBAAGjEDAOMAwGA1UdEwEB/wQCMAAwDQYJKoZI
hvcNAQELBQADggIBACKgK6DKbcSqLXitTW4jYtesmn/IO118heyGz3UHbcKXU1T/
Z9wm+9IKRPCJCG7qzK/5NYXCXYa5mGdKyFcRgDr9964a4IZFfns/pLZli3gLSi/2
xK+QAn2LyiBkP5+lMdXLopLdNEN1ZtPUMMTR9iPAIc2QMoH9QMZ+y8414PAjSOMC
K2FoVUSDp7f8Kiu7v/sP/emfQlPwF+jxtpRfG1pKUewO9KfASyW+EVjV2GStkZHu
PF4HMJNtyFpAxUX0UVOd3IhSWprH6Ly9fpJl0GygTPxhVSETRoW0hhs3XJVDISAh
VFYCK1ufhs544tNltGyFw2kO3ROkgGltgEMxjYUznMKNp/Gz3+b1k7Pwf5vdtLf8
B2caup+r0kPyfdkNyiaCOMN2tPotiQq+nSmTDdV6Z01bX+fKM2MSJt1YgIMlO2HE
U4rkt9n0zSsscwdqxMLU9pPVKscqPhX8Zwg2DxmHh4E8Ox80wx9M8NBBz9oMYsWJ
ak/u1qHEODv7reTpaG5H2/iLrQJuxj0rolAFlqZzdW95xRhSeTe5ccCvLCEALc0i
MD7AXZulBlsgOkKvolijvzBAlaY2nsFoR28JsIzIfznyBfqPRpouyRNmimwQ9TS8
qZHwov/yldCBMgIzkb/QIYcrA9rqx0JlMNmzRvmrSGp3WOwPYn2XUR1sz08+
-----END CERTIFICATE-----)";
    std::string org_name = "Grommunio";
    std::string app_name = "Gromox";
    std::string redirect_url = "http://localhost:8000/callback";
    std::string response_type = "code";
    std::string scope = "read";


private:
    Ui::MainWindow *ui;

    QWebEngineView *m_webview;
    QTcpServer *m_tcpserver;
    QTableView *m_tableview;
    CasdoorConfig *m_casdoor;
    QUrl *m_signin_url;

    void initButton();
    void initWebview();
    void initTable();
    void initCasdoorSDK();
    void initSigninUrl();
    void initTcpServer();

    void sendToServer(const QUrl& url);

    void resizeEvent(QResizeEvent *event);
    void sendUrlToServer();
    void setWebView();
    void sendMessage();
    servers *server;

    CasdoorConfig* getCasdoorSDK();

private slots:
    void on_tcp_connected();
    void on_auth_code_received(QUrl url);
    void on_pushButton_signout_clicked();
    void on_pushButton_signin_clicked();
};

#endif // MAINWINDOW_H
