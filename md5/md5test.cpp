//
// Created by Miguel Chan on 2018/11/21.
//

#include <iostream>
#include <unordered_map>
#include <fstream>
#include <sstream>
#include "md5test.h"
#include "md5.h"

using namespace std;

void md5StrTest(const std::string &input) {
    MD5 h;
    auto md5data = h.sum(input);
    cout << "MD5 (\'" << input << "\') = " << bytesToHexStr(md5data) << endl;
}

void md5FileTest(const char *filename) {
    ifstream fs(filename);
    stringstream buf;
    if (!fs.is_open()) {
        cerr << "md5: " << filename << ": No such file or directory" << endl;
        return;
    }
    buf << fs.rdbuf();
    MD5 h;
    auto md5Data = h.sum(buf.str());
    cout << "MD5 (" << filename << ") = " << bytesToHexStr(md5Data) << endl;
}

void md5RunTest() {

}

const unordered_map<unsigned char, char> hex_table = {
        {0x00, '0'}, {0x01, '1'}, {0x02, '2'}, {0x03, '3'}, {0x04, '4'},
        {0x05, '5'}, {0x06, '6'}, {0x07, '7'}, {0x08, '8'}, {0x09, '9'},
        {0x0a, 'a'}, {0x0b, 'b'}, {0x0c, 'c'}, {0x0d, 'd'}, {0x0e, 'e'},
        {0x0f, 'f'}
};

//Convert bytes array from md5 sum to a hex string
std::string bytesToHexStr(std::array<unsigned char, 16> data) {
    stringstream builder;
    for (int i = 0; i < 16; i++) {
        builder << hex_table.at((unsigned char)((data[i] >> 4) & 0x0f));
        builder << hex_table.at((unsigned char)(data[i] & 0x0f));
    }
    return builder.str();
}
