#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "MiniProjects/NumberTracker/mpnumbertracker.h"
#include "AESCryptography/aescryptography.h"

MainWindow::MainWindow(QWidget *parent) : QMainWindow(parent), ui(new Ui::MainWindow) {
    ui->setupUi(this);

    // Actions
    connect(ui->actionQuit, &QAction::triggered, this, &QApplication::quit);

    // Projects
    MPNumberTracker *mPNumberTracker = new MPNumberTracker(this);
    ui->stackedWidget->addWidget(mPNumberTracker);

    AESCryptography *aESCryptography = new AESCryptography(this);
    ui->stackedWidget->addWidget(aESCryptography);

    // Pages
    connect(ui->actionAbout, &QAction::triggered, this, [this]() {showPage("page_MainAbout");});
    connect(ui->actionCredits, &QAction::triggered, this, [this]() {showPage("page_MainCredits");});
    connect(ui->actionMPNumberTracker, &QAction::triggered, this, [this, mPNumberTracker]() {setPageWidget(mPNumberTracker);});
    connect(ui->actionAESCryptographyAbout, &QAction::triggered, this, [this, aESCryptography]() {setPageWidget(aESCryptography); aESCryptography->showPage("page_about");});
    connect(ui->actionAESCryptographyConvert, &QAction::triggered, this, [this, aESCryptography]() {setPageWidget(aESCryptography); aESCryptography->showPage("page_convert");});
    connect(ui->actionAESCryptographyEncrypt, &QAction::triggered, this, [this, aESCryptography]() {setPageWidget(aESCryptography); aESCryptography->showPage("page_encrypt");});
    connect(ui->actionAESCryptographyHash, &QAction::triggered, this, [this, aESCryptography]() {setPageWidget(aESCryptography); aESCryptography->showPage("page_hash");});
}

MainWindow::~MainWindow() {
    delete ui;
}

void MainWindow::showPage(const QString &pageName)
{
    auto page = ui->stackedWidget->findChild<QWidget*>(pageName);
    ui->stackedWidget->setCurrentWidget(page);
}

void MainWindow::setPageWidget(QWidget *widget) {
    ui->stackedWidget->setCurrentWidget(widget);
}
