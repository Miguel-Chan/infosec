//
// Created by Miguel Chan on 2018/11/21.
//

#ifndef MD5_MD5TEST_H
#define MD5_MD5TEST_H

#include <string>
#include <array>

void md5StrTest(const std::string& input);
void md5FileTest(const char* filename);
void md5TimeTest();
void md5RunTest();
std::string bytesToHexStr(std::array<unsigned char, 16> data);


#endif //MD5_MD5TEST_H
