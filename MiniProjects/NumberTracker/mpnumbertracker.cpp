#include "mpnumbertracker.h"
#include "ui_mpnumbertracker.h"

MPNumberTracker::MPNumberTracker(QWidget *parent) : QWidget(parent), ui(new Ui::MPNumberTracker) {
    ui->setupUi(this);

    trackedNumber = 0;

    // Add or Subtract
    connect(ui->buttonAdd1, &QPushButton::clicked, this, [this]() {changeTrackedNumber(1);});
    connect(ui->buttonAdd10, &QPushButton::clicked, this, [this]() {changeTrackedNumber(10);});
    connect(ui->buttonAdd100, &QPushButton::clicked, this, [this]() {changeTrackedNumber(100);});
    connect(ui->buttonSet0, &QPushButton::clicked, this, [this]() {setTrackedNumber(0);});
    connect(ui->buttonSubtract1, &QPushButton::clicked, this, [this]() {changeTrackedNumber(-1);});
    connect(ui->buttonSubtract10, &QPushButton::clicked, this, [this]() {changeTrackedNumber(-10);});
    connect(ui->buttonSubtract100, &QPushButton::clicked, this, [this]() {changeTrackedNumber(-100);});

    // Enter
    connect(ui->buttonAddNumber, &QPushButton::clicked, this, [this]() {enterNumber(Operation::Add);});
    connect(ui->buttonSubtractNumber, &QPushButton::clicked, this, [this]() {enterNumber(Operation::Subtract);});
    connect(ui->buttonSetNumber, &QPushButton::clicked, this, [this]() {enterNumber(Operation::Set);});
}

MPNumberTracker::~MPNumberTracker() {
    delete ui;
}

void MPNumberTracker::changeTrackedNumber(int changeBy) {
    trackedNumber += changeBy;
    ui->numberLCD->display(trackedNumber);
}

void MPNumberTracker::setTrackedNumber(int setTo) {
    trackedNumber = setTo;
    ui->numberLCD->display(trackedNumber);
}

void MPNumberTracker::enterNumber(Operation operation) {
    int enteredNumber;
    enteredNumber = ui->textEnterNumber->text().toInt();

    switch (operation) {
        case Operation::Add:
            changeTrackedNumber(enteredNumber);
            break;
        case Operation::Subtract:
            changeTrackedNumber(-enteredNumber);
            break;
        case Operation::Set:
            setTrackedNumber(enteredNumber);
            break;
    }
}
