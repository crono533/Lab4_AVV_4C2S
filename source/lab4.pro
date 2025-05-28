QT = core
CONFIG += c++17 cmdline


SOURCES += main.cpp \
           cryptersingleton.cpp


HEADERS += cryptersingleton.h


INCLUDEPATH += /usr/include/openssl

LIBS += -L/usr/lib/x86_64-linux-gnu -lcrypto -lssl
