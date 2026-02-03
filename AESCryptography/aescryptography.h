#ifndef AESCRYPTOGRAPHY_H
#define AESCRYPTOGRAPHY_H

#include <QWidget>

namespace Ui {
class AESCryptography;
}

class AESCryptography : public QWidget
{
    Q_OBJECT

public:
    explicit AESCryptography(QWidget *parent = nullptr);
    ~AESCryptography();

    void showPage(const QString &pageName);

private slots:
    void on_buttonEncrypt_clicked();
    void on_buttonDecrypt_clicked();
    void on_buttonHash_clicked();

private:
    Ui::AESCryptography *ui;

    enum class Format {
        PlainText,
        Hex,
        Bytes,
    };

    int readIterationCount();
    void copyTextToClipboard(const QString &text);
    void convertFromFormat(const Format format);
};

#endif // AESCRYPTOGRAPHY_H
