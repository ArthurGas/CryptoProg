#include <cryptopp/cryptlib.h>
#include <cryptopp/hex.h>
#include <cryptopp/files.h>
#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1
#include <cryptopp/md5.h>
#include <random>
#include <system_error>

namespace cpp = CryptoPP;
std::string hash(std::string file_name)
{
    std::string buf, h_str, res;
    std::ifstream file(file_name.c_str());
    if (file.is_open()) {
        if(file.peek() == std::ifstream::traits_type::eof())
            throw std::length_error("File is empty");
        while(getline(file, buf)) {
            cpp::Weak1::MD5 hash;
            cpp::StringSource ss( buf, true /* PumpAll */,
                                  new cpp::HashFilter( hash,
                                          new cpp::HexEncoder(new cpp::StringSink(h_str)))
                                );
            res+=h_str;
        }
        file.close();
        return(res);
    } else {
        throw std::system_error(errno, std::generic_category(), "Base read error");
    }
}
int main()
{
    try {
        std::cout<<hash("file.txt")<<'\n';
    } catch(const std::exception &e) {
        std::cerr<<e.what()<<std::endl;
    }
    return 0;
}


