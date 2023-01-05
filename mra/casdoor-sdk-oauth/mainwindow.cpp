#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <QTcpSocket>
#include <QUrl>
#include <QDebug>
#include <QMessageBox>
#include <iostream>
#include <thread>
// gromox application certificate

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


// gromox application privatekey

std::string Privatekey = R"(-----BEGIN RSA PRIVATE KEY-----
        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
        -----END RSA PRIVATE KEY-----)";

// creating a string to store the access token after it has been recieved from the oauth provider
std::string access;


void sendToServer();

// function to setup the mainwindow constructor
MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    ui->horizontalLayoutWidget->setStyleSheet("background-color:white;");
    ui->label_logo->setPixmap(QPixmap(":/assert/logo.png").scaledToHeight(ui->horizontalLayoutWidget->height()));

    // Initialize buttons
    initButton();

    // Initialize the QWebEngineView object
    initWebview();

    // Initialize the table of user information
    initTable();

    // Initialize casdoorSDK
    initCasdoorSDK();

    // Initialize the url of the login page
    initSigninUrl();

    // Initialize the TcpServer object
    initTcpServer();
}

// mainwindow destructor
MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::initButton()
{
    ui->pushButton_signout->hide();
    ui->pushButton_signin->show();
}

void MainWindow::initWebview()
{
    // Initialize the QWebEngineView object
    m_webview = new QWebEngineView(this);
    m_webview->resize(this->width(), this->height());

    // Hide the webview
    m_webview->hide();

    connect(m_webview, SIGNAL(urlChanged(QUrl)), this, SLOT(on_auth_code_received(QUrl)));
}

void MainWindow::initTable()
{
    // Initialize the QTableView object
    m_tableview = new QTableView(this);
    m_tableview->move(190, 80);
    m_tableview->resize(340, 150);

    // Hide the table
    m_tableview->hide();

}

void MainWindow::initCasdoorSDK()
{
    m_casdoor = getCasdoorSDK();
}

void MainWindow::initSigninUrl()
{
    QString *url = new QString("");
    url->append(QString("%1/login/oauth/authorize").arg(m_casdoor->getEndPoint().c_str()));
    url->append(QString("?client_id=%1").arg(m_casdoor->getClientId().c_str()));
    url->append(QString("&response_type=%1").arg(response_type.c_str()));
    url->append(QString("&redirect_uri=%1").arg(redirect_url.c_str()));
    url->append(QString("&scope=%1").arg(scope.c_str()));
    url->append(QString("&state=%1").arg(app_name.c_str()));

    m_signin_url = new QUrl(*url);
}

void MainWindow::initTcpServer()
{
    // Initialize the TcpServer object and listen on port 8000
    m_tcpserver = new QTcpServer(this);
    if(!m_tcpserver->listen(QHostAddress::LocalHost, 8000)) {
        qDebug() << m_tcpserver->errorString();
        close();
    }

    connect(m_tcpserver, SIGNAL(newConnection()), this, SLOT(on_tcp_connected()));
}

void MainWindow::resizeEvent(QResizeEvent *event)
{
    // Override the resizeEvent function to set the control adaptive page
    ui->horizontalLayoutWidget->resize(this->width(), ui->horizontalLayoutWidget->height());
    ui->pushButton_signin->move((this->width() - ui->pushButton_signin->width()) * 0.5, ui->pushButton_signin->y());
    ui->pushButton_signout->move((this->width() - ui->pushButton_signout->width()) * 0.5, ui->pushButton_signout->y());

    m_webview->resize(this->width(), this->height());

    m_tableview->move((this->width() - m_tableview->width()) * 0.5, m_tableview->y());
}

void MainWindow::setWebView()
{
    // Load and display the login page of Casdoor
    m_webview->page()->load(*m_signin_url);
    m_webview->show();
}

void MainWindow::sendMessage()
{
    // Return empty response
    QString response = "";

    // Get the socket of the established connection
    QTcpSocket *tcpsocket = m_tcpserver->nextPendingConnection();

    // Send data
    tcpsocket->write(response.toUtf8());
    // Disconnect
    tcpsocket->disconnectFromHost();
    tcpsocket->close();
    tcpsocket = NULL;
}

CasdoorConfig* MainWindow::getCasdoorSDK()
{
    CasdoorConfig* casdoor = new CasdoorConfig(
        endpoint,
        client_id,
        client_secret,
        certificate,
        org_name
    );

    return casdoor;
}

void MainWindow::on_tcp_connected()
{
    // Hide the webview
    m_webview->hide();

    // Send response data
    sendMessage();

    // Show the button of signout
    ui->pushButton_signout->show();
}


void MainWindow::on_auth_code_received(QUrl url)
{
    if(url.toString().startsWith("http://localhost:8000/callback")) {
        // Parse the code
        QString code = "";
        QStringList querys = url.query().split("&");
        for(const QString& query : querys) {
            QStringList pair = query.split("=");
            if(pair[0] == "code") {
                code = pair[1];
                break;
            }
        }

        // Get token and parse it with the JWT library
        std::string token = m_casdoor->GetOAuthToken(code.toStdString());
        auto decoded = m_casdoor->ParseJwtToken(token);

        access = token;

        // send users's details to server
        sendUrlToServer();
    }
}

void MainWindow::on_pushButton_signin_clicked()
{
    // hide the button of signin
    ui->pushButton_signin->hide();

    // Show the login page of Casdoor
    setWebView();
}

// Redirect to the IMAP/POP3 entrypoint
QUrl getEntrypointUrl(const std::string& protocol, const std::string& token, const std::string& certificate) {
    return QUrl(QString("http://localhost:8000/%1/login?token=%2&certificate=%3").arg(QString::fromStdString(protocol)).arg(QString::fromStdString(token)).arg(QString::fromStdString(certificate)));
}

// creating a url instance for the IMAP and POP3 servers
QUrl imap_entrypoint_url = getEntrypointUrl("imap", access, certificate);
QUrl pop3_entrypoint_url = getEntrypointUrl("pop3", access, certificate);


// create connection to server
void MainWindow::sendToServer(const QUrl& url) {

    // if the url is to be send to the IMAP entry point
    if (url == imap_entrypoint_url) {
        QTcpSocket imapSocket;
        imapSocket.connectToHost("localhost", 143);

        QDebug debug = qDebug();

        // wait for connection to be established
        if (!imapSocket.waitForConnected()) {
            debug << "Failed to connect to server:" << imapSocket.errorString();
            QMessageBox::critical(this, "IMAP Server", "Failed to connect to server: " + imapSocket.errorString());
            return;
        }
        else {
            imapSocket.write(imap_entrypoint_url.toString().toUtf8());
            imapSocket.flush();
            QMessageBox::information(this, "IMAP Server", "Connecting...");

            // Wait until the request is sent
            if (!imapSocket.waitForBytesWritten()) {
                debug << "Error: Could not send request";
                QMessageBox::critical(this, "IMAP Server", "Error: Could not send request");
                return;
            }

            // Read the response from the server
            QByteArray imapResponse;
            while (imapSocket.waitForReadyRead()) {
                imapResponse += imapSocket.readAll();
            }

            // Print the response to the console
            debug << "Response from server:";
            debug << imapResponse;
            QMessageBox::information(this, "IMAP Server", "Response from server: " + imapResponse);
        }
    }

    // if the url is to be send to the POP3 entry point
    else if (url == pop3_entrypoint_url) {
        QTcpSocket pop3Socket;
        QDebug debug = qDebug();
        pop3Socket.connectToHost("localhost", 110);

        // wait for connection to be established
        if (!pop3Socket.waitForConnected()) {
            debug << "Failed to connect to server:" << pop3Socket.errorString();
            QMessageBox::critical(this, "POP3 Server", "Failed to connect to server " + pop3Socket.errorString());
            return;
        }
        else {
            pop3Socket.write(pop3_entrypoint_url.toString().toUtf8());
            pop3Socket.flush();
            QMessageBox::information(this, "POP3 Server", "Connecting...");

            // Wait until the request is sent
            if (!pop3Socket.waitForBytesWritten()) {
                debug << "Error: Could not send request";
                QMessageBox::critical(this, "POP3 Server", "Error: Could not send request");
                return;
            }

            // Read the response from the server
            QByteArray pop3Response;
            while (pop3Socket.waitForReadyRead()) {
                pop3Response += pop3Socket.readAll();
            }

            // Print the response to the console
            debug << "Response from server:";
            debug << pop3Response;
            QMessageBox::information(this, "POP3 Server", "Response from server: " + pop3Response);
        }
    }
}

// send url to imap/pop3 entry point wait for response
void MainWindow::sendUrlToServer() {
    hide();
    server = new servers(this);
    server->show();
    server->setWindowTitle("Servers");

    // send to IMAP server
    sendToServer(imap_entrypoint_url);

    // send to POP3 server
    sendToServer(pop3_entrypoint_url);
}


void MainWindow::on_pushButton_signout_clicked()
{
    // Hide the table of user information
    m_tableview->hide();

    // Hide the button of signout
    ui->pushButton_signout->hide();

    // Show the button of signin
    ui->pushButton_signin->show();
}
