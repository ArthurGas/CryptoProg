#include <cryptopp/cryptlib.h>
#include <cryptopp/hex.h>
#include <cryptopp/files.h>
#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1
#include <cryptopp/md5.h>
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/filters.h>
#include <cryptopp/osrng.h>
#include <cryptopp/pwdbased.h>
#include <cryptopp/files.h>
#include <system_error>
#include <exception>
namespace cpp = CryptoPP;
void encrypt(const std::string ifilename, const std::string ofilename="encr.txt", const std::string password="123_privet_123")
{
    std::string buf, res;

    cpp::AutoSeededRandomPool prng; //псевдосл. генератор

    cpp::SecByteBlock key(cpp::AES::DEFAULT_KEYLENGTH);
    cpp::PKCS5_PBKDF2_HMAC<cpp::Weak1::MD5> kobj; //объект для генерации ключа
    kobj.DeriveKey(key, key.size(), 0, (cpp::byte*)password.data(), password.size(), (cpp::byte*)"", 0, 1000); // генерация ключа из пароля

    cpp::byte iv[cpp::AES::BLOCKSIZE];// Initialization vector
    prng.GenerateBlock(iv, sizeof(iv)); // генерация IV
    std::ofstream ivfile("ivfile", std::ios::binary);
    ivfile.write((char*)(iv), cpp::AES::BLOCKSIZE); //запись IV в спец. файл
    ivfile.close();

    //шифрование

    cpp::CBC_Mode<cpp::AES>::Encryption encr;
    // set IV and Key to cipher
    encr.SetKeyWithIV( key, sizeof(key), iv );
    std::ifstream ifile(ifilename, std::ios::binary);
    std::ofstream ofile(ofilename, std::ios::binary);

    cpp::FileSource (ifile, true,
                     new cpp::StreamTransformationFilter(encr,
                             new cpp::FileSink(ofile))
                    );
    std::clog << "File " << ifilename << " encrypted and stored to " << ofilename << std::endl;
    ifile.close();
    ofile.close();
}
void decrypt(const std::string ifilename, const std::string ofilename, const std::string password)
{
    cpp::AutoSeededRandomPool prng; //псевдосл. генератор

    cpp::SecByteBlock key(cpp::AES::DEFAULT_KEYLENGTH);
    cpp::PKCS5_PBKDF2_HMAC<cpp::Weak1::MD5> kobj; //объект для генерации ключа
    kobj.DeriveKey(key, key.size(), 0, (cpp::byte*)password.data(), password.size(), (cpp::byte*)"", 0, 1000); // генерация ключа из пароля

    cpp::byte iv[cpp::AES::BLOCKSIZE];// Initialization vector
    std::ifstream ivfile("ivfile", std::ios::binary);
    ivfile.read(reinterpret_cast<char*>(iv), cpp::AES::BLOCKSIZE);
    ivfile.close();

    //расшифрование

    cpp::CBC_Mode<cpp::AES>::Decryption decr;
    // set IV and Key to cipher
    decr.SetKeyWithIV(key, sizeof(key), iv);
    std::ifstream ifile(ifilename, std::ios::binary);
    std::ofstream ofile(ofilename, std::ios::binary);

    cpp::FileSource (ifile, true,
                     new cpp::StreamTransformationFilter(decr,
                             new cpp::FileSink(ofile))
                    );
    std::clog << "File " << ifilename << " decrypted and stored to " << ofilename << std::endl;
    ifile.close();
    ofile.close();
}
int main(int argc, char **argv)
{
    try {
        uint option;
        std::string textfile, encrfile, password;
        std::cout << "Программа для шифрования"<< '\n';
        std::cout << "Выберите действие(1-зашифрование 2-расшифрование):";
        std::cin >> option;
        if (option!=1 && option!=2) {
            throw(std::invalid_argument("Wrong option"));
        } else if(option==1) {
            std::cout << "Введите файл с текстом для зашифровки:";
            std::cin >> textfile;
            std::cout << "Введите файл для зашифрованного текста:";
            std::cin >> encrfile;
            std::cout << "Введите пароль:";
            std::cin >> password;
            encrypt(textfile, encrfile, password);
        }else{
            std::cout << "Введите файл с текстом для расшифровки:";
            std::cin >> encrfile;
            std::cout << "Введите файл для результатов расшифрования текста:";
            std::cin >> textfile;
            std::cout << "Введите пароль:";
            std::cin >> password;
            decrypt(encrfile, textfile, password);
        }
    } catch(const std::exception &e) {
        std::cerr << e.what() << std::endl;
    }
    return 0;
}
