TEMPLATE = app
CONFIG -= app_bundle
CONFIG -= qt
CONFIG += console c++11
LIBS += -lssl -lcrypto

SOURCES += \
        main.cpp \
    verifiablerandom.cpp

HEADERS += \
    verifiablerandom.h
