<h1 align="center" style="border-bottom: none;">📦⚡️casdoor cpp qt example</h1>
<h3 align="center">An example of casdoor-cpp-sdk</h3>

## Architecture

Example contains 2 parts:

| Name     | SDK              | Language         | Source code                                                     |
| -------- | ---------------- | ---------------- | --------------------------------------------------------------- |
| Frontend | Qt SDK  | Qt | https://github.com/casdoor/casdoor-cpp-qt-example |
| Backend  | casdoor-cpp-sdk | c++             | https://github.com/casdoor/casdoor-cpp-sdk                |

## Installation

Example uses Casdoor to manage members. So you need to create an organization and an application for the example in a Casdoor instance.

### Necessary configuration

#### Get the code

```shell
git clone https://github.com/casdoor/casdoor
git clone https://github.com/casdoor/casdoor-cpp-qt-example
```

#### Run example

- run casdoor
- configure
- Front end

    ```qt
    // in ./casdoor-cpp-qt-example.pro
    INCLUDEPATH += $$quote(D:/Program Files/OpenSSL-Win64/include) // installation path of OpenSSL
    ```

    ```qt
    // in ./mainwindow.cpp
    m_tcpserver->listen(QHostAddress::LocalHost, 8080); // port where tcp server listen
    ```

    ```qt
    // in ./mainwindow.cpp
    CasdoorConfig* casdoor = new CasdoorConfig(
        "http://localhost:8000", // Casdoor Server Url
        "3efd29ff3e0b14ba1dd7", // client id
        "34cb65d634b06a49f14c6bc49884ce1df55ce518", // client secret
        cert, // certificate
        "built-in" // organization
    );
    ```

- run qt example

Now, example runs its front end at port 8080. You can modify the code and see what will happen.
