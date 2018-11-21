//
// Created by Miguel Chan on 2018/11/21.
//

#ifndef MD5_MD5_H
#define MD5_MD5_H

#include <cstddef>
#include <vector>
#include <string>
#include <array>

class MD5 {
private:
    std::array<unsigned char, 16> md5Sum(std::vector<unsigned char> data);
    void padding(std::vector<unsigned char> & data);
    static const std::array<unsigned char, 16> initialVector;
    static const std::array<uint32_t, 64> t_table;
    static const std::array<unsigned int, 64> s_table;
    static const std::array<unsigned int, 64> x_table;
    uint32_t circularLeftShift(uint32_t data, unsigned int c);
    std::array<unsigned char, 16> HMD5(const std::array<unsigned char, 64> &data,
                                       const std::array<unsigned char, 16> &cv);

public:
    std::array<unsigned char, 16> sum(const std::vector<unsigned char> &data);
    std::array<unsigned char, 16> sum(const std::string &data);
};


#endif //MD5_MD5_H
