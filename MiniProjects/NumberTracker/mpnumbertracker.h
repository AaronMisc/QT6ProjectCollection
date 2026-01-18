#ifndef MPNUMBERTRACKER_H
#define MPNUMBERTRACKER_H

#include <QWidget>
#include <QLCDNumber>
#include <QLineEdit>

namespace Ui {
class MPNumberTracker;
}

class MPNumberTracker : public QWidget
{
    Q_OBJECT

public:
    explicit MPNumberTracker(QWidget *parent = nullptr);
    ~MPNumberTracker();

private:
    Ui::MPNumberTracker *ui;

    enum class Operation {
        Add,
        Subtract,
        Set,
    };

    int trackedNumber;
    void changeTrackedNumber(int changeBy);
    void setTrackedNumber(int setTo);
    void enterNumber(Operation operation);
};

#endif // MPNUMBERTRACKER_H
