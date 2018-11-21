//
// Created by Miguel Chan on 2018/11/21.
//

#include <iostream>
#include <unordered_map>
#include <fstream>
#include <sstream>
#include <unordered_map>
#include <ctime>
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

vector<pair<string, string>> hexResult = {
        {"", "d41d8cd98f00b204e9800998ecf8427e"},
        {"a", "0cc175b9c0f1b6a831c399e269772661"},
        {"abc", "900150983cd24fb0d6963f7d28e17f72"},
        {"message digest", "f96b697d7cb7938d525a2f31aaf161d0"},
        {"abcdefghijklmnopqrstuvwxyz", "c3fcd3d76192e4007dfb496cca67e13b"},
        {"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
                "d174ab98d277d9f5a5611c2c9f419d9f"},
        {"12345678901234567890123456789012345678901234567890123456789012345678901234567890",
                "57edf4a22be3c955ac49da2e2107b67a"},
        {"MD5 has not yet (2001-09-03) been broken, but sufficient attacks have been made that its security is in some doubt",
                "b50663f41d44d92171cb9976bc118538"}
};

void md5RunTest() {
    MD5 h;
    // Result Test
    cout << "MD5 test suite:" << endl;
    for (auto p : hexResult) {
        auto md5Data = h.sum(p.first);
        auto md5Hex = bytesToHexStr(md5Data);
        cout << "MD5 (\'" << p.first << "\') = " << md5Hex;
        if (md5Hex == p.second) {
            cout << " - verified correct" << endl;
        } else {
            cout << " - verified fail" << endl;
        }
    }
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
