#include "aescryptography.h"
#include "ui_aescryptography.h"
// #include <QCoreApplication>
#include <QByteArray>
#include <QCryptographicHash>
#include <QRandomGenerator>
#include <QClipboard>

#include <openssl/evp.h>
#include <openssl/rand.h>

AESCryptography::AESCryptography(QWidget *parent)
    : QWidget(parent)
    , ui(new Ui::AESCryptography)
{
    ui->setupUi(this);

    connect(ui->buttonEncryptCopyPlainText, &QPushButton::clicked, this, [this](){copyTextToClipboard(ui->encryptPlainTextEdit->toPlainText());});
    connect(ui->buttonCopyCipherText, &QPushButton::clicked, this, [this](){copyTextToClipboard(ui->cipherTextEdit->toPlainText());});
}

AESCryptography::~AESCryptography()
{
    delete ui;
}

inline const unsigned char* asUnsignedBytes(const QByteArray &b) {
    return reinterpret_cast<const unsigned char*>(b.constData());
}

inline unsigned char* asUnsignedBytes(QByteArray &b) {
    return reinterpret_cast<unsigned char*>(b.data());
}

struct EvpCtx {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    ~EvpCtx() { EVP_CIPHER_CTX_free(ctx); }
};

void initializeAesGcm(
    EVP_CIPHER_CTX* ctx,
    const QByteArray &key,
    const QByteArray &iv,
    bool encrypt
    ) {
    if (encrypt) {
        EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv.size(), nullptr);
        EVP_EncryptInit_ex(ctx, nullptr, nullptr, asUnsignedBytes(key), asUnsignedBytes(iv));
    } else {
        EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv.size(), nullptr);
        EVP_DecryptInit_ex(ctx, nullptr, nullptr, asUnsignedBytes(key), asUnsignedBytes(iv));
    }
}

QByteArray randomBytes(int size) {
    QByteArray b(size, Qt::Uninitialized);
    RAND_bytes(asUnsignedBytes(b), size);
    return b;
}

QByteArray hashSHA256(const QString &passphrase) {
    return QCryptographicHash::hash(
        passphrase.toUtf8(),
        QCryptographicHash::Sha256
    );
}

QByteArray aesEncrypt(const QString &plaintext, const QString &passphrase) {
    QByteArray key = hashSHA256(passphrase);
    QByteArray iv  = randomBytes(12);   // GCM standard
    QByteArray tag(16, Qt::Uninitialized);

    EvpCtx evp;

    initializeAesGcm(evp.ctx, key, iv, true);

    QByteArray input = plaintext.toUtf8();
    QByteArray cipher(input.size(), Qt::Uninitialized);

    int len = 0;
    EVP_EncryptUpdate(evp.ctx, asUnsignedBytes(cipher), &len, asUnsignedBytes(input), input.size());
    cipher.resize(len);

    EVP_EncryptFinal_ex(evp.ctx, nullptr, &len);

    EVP_CIPHER_CTX_ctrl(evp.ctx, EVP_CTRL_GCM_GET_TAG, tag.size(), tag.data());

    return (iv + tag + cipher).toBase64();
}

QString aesDecrypt(const QByteArray &encryptedBase64, const QString &passphrase) {
    QByteArray raw = QByteArray::fromBase64(encryptedBase64);
    if (raw.size() < 28) return {}; // IV + TAG minimum

    QByteArray iv   = raw.left(12);
    QByteArray tag  = raw.mid(12, 16);
    QByteArray data = raw.mid(28);

    QByteArray key = hashSHA256(passphrase);
    QByteArray out(data.size(), Qt::Uninitialized);

    EvpCtx evp;
    initializeAesGcm(evp.ctx, key, iv, false);

    int len = 0;
    EVP_DecryptUpdate(evp.ctx, asUnsignedBytes(out), &len, asUnsignedBytes(data), data.size());

    EVP_CIPHER_CTX_ctrl(evp.ctx, EVP_CTRL_GCM_SET_TAG, tag.size(), tag.data());

    if (EVP_DecryptFinal_ex(evp.ctx, asUnsignedBytes(out) + len, &len) <= 0)
        return {}; // authentication failed

    out.resize(len + out.size());
    return QString::fromUtf8(out);
}

/**
int main(int argc, char *argv[]) {
    QCoreApplication app(argc, argv);
    QTextStream out(stdout);

    QString secretText = "This is highly confidential text.";
    QString passphrase = "correct horse battery staple";

    QByteArray encrypted = aesEncrypt(secretText, passphrase);
    QString decrypted = aesDecrypt(encrypted, passphrase);

    out << "Original:  " << secretText << "\n";
    out << "Encrypted: " << encrypted << "\n";
    out << "Decrypted: " << decrypted << "\n";

    return 0;
}
**/

void AESCryptography::on_buttonEncrypt_clicked() {
    QString plaintext = ui->encryptPlainTextEdit->toPlainText();
    QString passphrase = ui->encryptPassphrase->text();

    QByteArray encrypted = aesEncrypt(plaintext, passphrase);

    ui->cipherTextEdit->setPlainText(
        QString::fromUtf8(encrypted)
    );
}

void AESCryptography::on_buttonDecrypt_clicked() {
    QString encryptedText = ui->cipherTextEdit->toPlainText();
    QString passphrase = ui->encryptPassphrase->text();

    QString decrypted = aesDecrypt(encryptedText.toUtf8(), passphrase);

    ui->encryptPlainTextEdit->setPlainText(decrypted);
}

void AESCryptography::showPage(const QString &pageName)
{
    auto page = ui->stackedWidget->findChild<QWidget*>(pageName);
    ui->stackedWidget->setCurrentWidget(page);
}

void AESCryptography::1copyTextToClipboard(const QString &text)
{
    QClipboard *clipboard = QApplication::clipboard();
    clipboard->setText(text);
}
