cmake_minimum_required(VERSION 3.19)
project(QTProjectCollection LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(Qt6 6.5 REQUIRED COMPONENTS Core Widgets)
find_package(OpenSSL REQUIRED)

qt_standard_project_setup()

qt_add_executable(QTProjectCollection
    WIN32 MACOSX_BUNDLE
    main.cpp
    mainwindow.h mainwindow.cpp mainwindow.ui
    MiniProjects/NumberTracker/mpnumbertracker.h MiniProjects/NumberTracker/mpnumbertracker.cpp MiniProjects/NumberTracker/mpnumbertracker.ui
    AESCryptography/aescryptography.h AESCryptography/aescryptography.cpp AESCryptography/aescryptography.ui
    QTProjectCollectionData.json
)

target_link_libraries(QTProjectCollection
    PRIVATE
        Qt::Core
        Qt::Widgets
        OpenSSL::Crypto
)

include(GNUInstallDirs)

install(TARGETS QTProjectCollection
    BUNDLE  DESTINATION .
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
)

qt_generate_deploy_app_script(
    TARGET QTProjectCollection
    OUTPUT_SCRIPT deploy_script
    NO_UNSUPPORTED_PLATFORM_ERROR
)
install(SCRIPT ${deploy_script})
