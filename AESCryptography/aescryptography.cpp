#include "aescryptography.h"
#include "ui_aescryptography.h"
// #include <QCoreApplication>
#include <QByteArray>
#include <QCryptographicHash>
#include <QRandomGenerator>
#include <QClipboard>
#include <QDebug>
#include <QRegularExpression>

#include <openssl/evp.h>
#include <openssl/rand.h>

constexpr int AES_KEY_SIZE = 32;
constexpr int GCM_IV_SIZE  = 12;
constexpr int GCM_TAG_SIZE = 16;
constexpr int SALT_SIZE    = 16;
constexpr unsigned char FORMAT_VERSION = 0x01;

AESCryptography::AESCryptography(QWidget *parent)
    : QWidget(parent)
    , ui(new Ui::AESCryptography)
{
    ui->setupUi(this);

    // Copy buttons
    connect(ui->buttonEncryptCopyPlainText, &QPushButton::clicked, this, [this](){copyTextToClipboard(ui->encryptPlainTextEdit->toPlainText());});
    connect(ui->buttonCopyCipherText, &QPushButton::clicked, this, [this](){copyTextToClipboard(ui->cipherTextEdit->toPlainText());});
    connect(ui->buttonCopyHashedText, &QPushButton::clicked, this, [this](){copyTextToClipboard(ui->hashedTextEdit->toPlainText());});
    connect(ui->buttonConvertCopyPlainText, &QPushButton::clicked, this, [this](){copyTextToClipboard(ui->convertPlainTextEdit->toPlainText());});
    connect(ui->buttonConvertCopyBytes, &QPushButton::clicked, this, [this](){copyTextToClipboard(ui->bytesTextEdit->toPlainText());});
    connect(ui->buttonConvertCopyHex, &QPushButton::clicked, this, [this](){copyTextToClipboard(ui->hexTextEdit->toPlainText());});

    // Convert page
    connect(ui->buttonConvertPlainText, &QPushButton::clicked, this, [this](){convertFromFormat(Format::PlainText);});
    connect(ui->buttonConvertBytes, &QPushButton::clicked, this, [this](){convertFromFormat(Format::Bytes);});
    connect(ui->buttonConvertHex, &QPushButton::clicked, this, [this](){convertFromFormat(Format::Hex);});
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

QByteArray secureRandomBytes(int size)
{
    QByteArray b(size, Qt::Uninitialized);
    if (RAND_bytes(asUnsignedBytes(b), size) != 1)
        qWarning() << "RAND_bytes failed";
    return b;
}

QByteArray hashSHA256(const QString &passphrase) {
    return QCryptographicHash::hash(
        passphrase.toUtf8(),
        QCryptographicHash::Sha256
    );
}

QByteArray deriveKeyPBKDF2(
    const QString& passphrase,
    const QByteArray& salt,
    int iterations
    ) {
    QByteArray key(AES_KEY_SIZE, Qt::Uninitialized);

    if (PKCS5_PBKDF2_HMAC(
            passphrase.toUtf8().constData(),
            passphrase.size(),
            asUnsignedBytes(salt),
            salt.size(),
            iterations,
            EVP_sha256(),
            key.size(),
            asUnsignedBytes(key)
            ) != 1) {
        qWarning() << "PBKDF2 failed";
    }

    return key;
}

int AESCryptography::readIterationCount() {
    int iters = ui->encryptIterations->text().toInt();

    if (iters < 300000)
        qWarning() << "Low PBKDF2 iteration count";

    return iters;
}

QByteArray aesEncrypt(
    const QString& plaintext,
    const QString& passphrase,
    int iterations
    ) {
    QByteArray salt = secureRandomBytes(SALT_SIZE);
    QByteArray iv   = secureRandomBytes(GCM_IV_SIZE);
    QByteArray key  = deriveKeyPBKDF2(passphrase, salt, iterations);

    EvpCtx evp;

    if (EVP_EncryptInit_ex(evp.ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1)
        qWarning() << "EncryptInit failed";

    if (EVP_CIPHER_CTX_ctrl(evp.ctx, EVP_CTRL_GCM_SET_IVLEN, iv.size(), nullptr) != 1)
        qWarning() << "Set IV length failed";

    if (EVP_EncryptInit_ex(
            evp.ctx, nullptr, nullptr,
            asUnsignedBytes(key),
            asUnsignedBytes(iv)
            ) != 1)
        qWarning() << "EncryptInit key/iv failed";

    QByteArray input  = plaintext.toUtf8();
    QByteArray cipher(input.size(), Qt::Uninitialized);

    int outLen   = 0;
    int totalLen = 0;

    if (EVP_EncryptUpdate(
            evp.ctx,
            asUnsignedBytes(cipher),
            &outLen,
            asUnsignedBytes(input),
            input.size()
            ) != 1)
        qWarning() << "EncryptUpdate failed";

    totalLen += outLen;

    if (EVP_EncryptFinal_ex(
            evp.ctx,
            asUnsignedBytes(cipher) + totalLen,
            &outLen
            ) != 1)
        qWarning() << "EncryptFinal failed";

    totalLen += outLen;

    QByteArray tag(GCM_TAG_SIZE, Qt::Uninitialized);

    if (EVP_CIPHER_CTX_ctrl(
            evp.ctx,
            EVP_CTRL_GCM_GET_TAG,
            tag.size(),
            asUnsignedBytes(tag)
            ) != 1)
        qWarning() << "Get TAG failed";

    cipher.resize(totalLen);

    QByteArray result;
    result.append(FORMAT_VERSION);

    quint32 itersBE = qToBigEndian(static_cast<quint32>(iterations));
    result.append(reinterpret_cast<const char*>(&itersBE), sizeof(itersBE));

    result.append(salt);
    result.append(iv);
    result.append(tag);
    result.append(cipher);

    return result.toBase64();
}

QString aesDecrypt(
    const QByteArray& encryptedBase64,
    const QString& passphrase
    ) {
    QByteArray raw = QByteArray::fromBase64(encryptedBase64);

    int offset = 0;

    unsigned char version = raw[offset++];
    if (version != FORMAT_VERSION)
        return {};

    if (raw.size() < offset + sizeof(quint32))
        return {};

    quint32 itersBE;
    memcpy(&itersBE, raw.constData() + offset, sizeof(itersBE));
    int iterations = qFromBigEndian(itersBE);
    offset += sizeof(itersBE);

    QByteArray salt = raw.mid(offset, SALT_SIZE);
    offset += SALT_SIZE;

    QByteArray iv = raw.mid(offset, GCM_IV_SIZE);
    offset += GCM_IV_SIZE;

    QByteArray tag = raw.mid(offset, GCM_TAG_SIZE);
    offset += GCM_TAG_SIZE;

    QByteArray cipher = raw.mid(offset);

    QByteArray key = deriveKeyPBKDF2(passphrase, salt, iterations);

    EvpCtx evp;

    if (EVP_DecryptInit_ex(evp.ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1)
        return {};

    if (EVP_CIPHER_CTX_ctrl(evp.ctx, EVP_CTRL_GCM_SET_IVLEN, iv.size(), nullptr) != 1)
        return {};

    if (EVP_DecryptInit_ex(
            evp.ctx, nullptr, nullptr,
            asUnsignedBytes(key),
            asUnsignedBytes(iv)
            ) != 1)
        return {};

    QByteArray output(cipher.size(), Qt::Uninitialized);

    int outLen   = 0;
    int totalLen = 0;

    if (EVP_DecryptUpdate(
            evp.ctx,
            asUnsignedBytes(output),
            &outLen,
            asUnsignedBytes(cipher),
            cipher.size()
            ) != 1)
        return {};

    totalLen += outLen;

    if (EVP_CIPHER_CTX_ctrl(
            evp.ctx,
            EVP_CTRL_GCM_SET_TAG,
            tag.size(),
            asUnsignedBytes(tag)
            ) != 1)
        return {};

    if (EVP_DecryptFinal_ex(
            evp.ctx,
            asUnsignedBytes(output) + totalLen,
            &outLen
            ) <= 0)
        return {};

    totalLen += outLen;
    output.resize(totalLen);

    return QString::fromUtf8(output);
}

void AESCryptography::on_buttonEncrypt_clicked() {
    QString plaintext  = ui->encryptPlainTextEdit->toPlainText();
    QString passphrase = ui->encryptPassphrase->text();

    int iterations = readIterationCount();

    QByteArray encrypted = aesEncrypt(plaintext, passphrase, iterations);
    ui->cipherTextEdit->setPlainText(QString::fromUtf8(encrypted));
}

void AESCryptography::on_buttonDecrypt_clicked() {
    QString encryptedText = ui->cipherTextEdit->toPlainText();
    QString passphrase = ui->encryptPassphrase->text();

    QString decrypted = aesDecrypt(encryptedText.toUtf8(), passphrase);

    ui->encryptPlainTextEdit->setPlainText(decrypted);
}

void AESCryptography::showPage(const QString &pageName) {
    auto page = ui->stackedWidget->findChild<QWidget*>(pageName);
    ui->stackedWidget->setCurrentWidget(page);
}

void AESCryptography::copyTextToClipboard(const QString &text) {
    QClipboard *clipboard = QApplication::clipboard();
    clipboard->setText(text);
}

void AESCryptography::on_buttonHash_clicked() {
    QByteArray hashedBytes = hashSHA256(ui->hashPlainTextEdit->toPlainText());
    QString hashedText = hashedBytes.toHex();

    ui->hashedTextEdit->setPlainText(hashedText);
}

QString bytesToHex(const QByteArray& bytes)
{
    QString hex;
    for (unsigned char b : bytes)
        hex += QString("%1 ").arg(b, 2, 16, QChar('0'));
    return hex.trimmed();
}

QString bytesToDecimal(const QByteArray& bytes)
{
    QString out;
    for (unsigned char b : bytes)
        out += QString::number(b) + " ";
    return out.trimmed();
}

QByteArray hexToBytes(const QString& hex)
{
    QString cleaned = hex;
    cleaned.remove(' ');

    return QByteArray::fromHex(cleaned.toUtf8());
}

QByteArray decimalToBytes(const QString& text)
{
    QByteArray out;
    const QStringList parts = text.split(QRegularExpression("\\s+"), Qt::SkipEmptyParts);

    for (const QString& part : parts) {
        bool ok = false;
        int value = part.toInt(&ok);
        if (!ok || value < 0 || value > 255)
            qWarning() << "Error converting decimal to bytes";
            return {};
        out.append(static_cast<char>(value));
    }
    return out;
}

void AESCryptography::convertFromFormat(const Format format)
{
    QPlainTextEdit* plainTextEdit = ui->convertPlainTextEdit;
    QPlainTextEdit* hexTextEdit   = ui->hexTextEdit;
    QPlainTextEdit* bytesTextEdit = ui->bytesTextEdit;

    switch (format)
    {
    case Format::PlainText: {
        QByteArray bytes =
            plainTextEdit->toPlainText().toUtf8();

        hexTextEdit->setPlainText(bytesToHex(bytes));
        bytesTextEdit->setPlainText(bytesToDecimal(bytes));
        break;
    }

    case Format::Hex: {
        QByteArray bytes =
            hexToBytes(hexTextEdit->toPlainText());

        plainTextEdit->setPlainText(QString::fromUtf8(bytes));
        bytesTextEdit->setPlainText(bytesToDecimal(bytes));
        break;
    }

    case Format::Bytes: {
        QByteArray bytes =
            decimalToBytes(bytesTextEdit->toPlainText());

        plainTextEdit->setPlainText(QString::fromUtf8(bytes));
        hexTextEdit->setPlainText(bytesToHex(bytes));
        break;
    }
    }
}

