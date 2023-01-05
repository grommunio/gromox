#-------------------------------------------------
#
# Project created by QtCreator 2022-09-10T10:57:37
#
#-------------------------------------------------

QT += core gui
QT += network
QT += webenginewidgets
QT += webchannel

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

TARGET = casdoor-cpp-qt-example
TEMPLATE = app

# The following define makes your compiler emit warnings if you use
# any feature of Qt which has been marked as deprecated (the exact warnings
# depend on your compiler). Please consult the documentation of the
# deprecated API in order to know how to port your code away from it.
DEFINES += QT_DEPRECATED_WARNINGS

# You can also make your code fail to compile if you use deprecated APIs.
# In order to do so, uncomment the following line.
# You can also select to disable deprecated APIs only up to a certain version of Qt.
DEFINES += QT_DISABLE_DEPRECATED_BEFORE=0x060000    # disables all the APIs deprecated before Qt 6.0.0

CONFIG += c++14

SOURCES += \
        casdoor/src/casdoor_config.cpp \
        casdoor/src/casdoor_user.cpp \
        casdoor/src/json/jsoncpp.cpp \
        main.cpp \
        mainwindow.cpp \
        servers.cpp

HEADERS += \
        casdoor/include/casdoor_config.h \
        casdoor/include/casdoor_user.h \
        casdoor/include/httplib/httplib.h \
        casdoor/include/json/json.h \
        casdoor/include/jwt-cpp/base.h \
        casdoor/include/jwt-cpp/jwt.h \
        casdoor/include/picojson/picojson.h \
        mainwindow.h \
        servers.h

FORMS += \
        mainwindow.ui \
        servers.ui

LIBS += -lWs2_32

INCLUDEPATH += $$quote(C:/Program Files/OpenSSL-Win64/include)
INCLUDEPATH += ./casdoor/include
INCLUDEPATH += ./casdoor/src


# Default rules for deployment.
qnx: target.path = /tmp/$${TARGET}/bin
else: unix:!android: target.path = /opt/$${TARGET}/bin
!isEmpty(target.path): INSTALLS += target

RESOURCES += \
    assert/assert.qrc
