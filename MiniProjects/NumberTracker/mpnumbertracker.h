#ifndef MPNUMBERTRACKER_H
#define MPNUMBERTRACKER_H

#include <QWidget>
#include <QLCDNumber>
#include <QLineEdit>
#include <QJsonDocument>
#include <QJsonObject>
#include <QString>
#include <QFile>

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
    int getNumberTrackerValue(const QString &key);
    void setNumberTrackerValue(const QString &key, int value);
    void saveNumberTrackerJson(const QJsonObject &root);
    QString getSlotNumber();
};

#endif // MPNUMBERTRACKER_H
