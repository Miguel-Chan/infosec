//
// Created by Miguel Chan on 2018/11/21.
//

#include "md5.h"
#include <functional>
#include <climits>
#include <cstring>

using namespace std;

const array<unsigned char, 16> MD5::initialVector = {
    0x01, 0x23, 0x45, 0x67,
    0x89, 0xab, 0xcd, 0xef,
    0xfe, 0xdc, 0xba, 0x98,
    0x76, 0x54, 0x32, 0x10
};

const std::array<uint32_t, 64> MD5::t_table = {
        0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
        0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
        0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
        0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
        0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
        0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
        0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
        0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
        0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
        0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
        0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
        0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
        0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
        0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
        0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
        0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
};

const std::array<unsigned int, 64> MD5::s_table = {
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
        5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
        4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
        6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
};

const std::array<unsigned int, 64> MD5::x_table = {
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
        1, 6, 11, 0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12,
        5, 8, 11, 14, 1, 4, 7, 10, 13, 0, 3, 6, 9, 12, 15, 2,
        0, 7, 14, 5, 12, 3, 10, 1, 8, 15, 6, 13, 4, 11, 2, 9
};


array<unsigned char, 16> MD5::md5Sum(std::vector<unsigned char> data) {
    padding(data);

    array<unsigned char, 16> cv(initialVector);

    // Divide into blocks and start iteration
    // Each step is a block of 64 bytes(512 bits)
    for (int i = 0; i < data.size(); i += 64) {
        array<unsigned char, 64> block{};
        copy(begin(data) + i, begin(data) + i + 64, begin(block));
        cv = HMD5(block, cv);
    }

    return cv;
}

array<unsigned char, 16> MD5::sum(const std::string &data) {
    const auto * dataArr = reinterpret_cast<const unsigned char*>(data.c_str());
    vector<unsigned char> dataVec(dataArr, dataArr + data.size());
    return md5Sum(dataVec);
}

array<unsigned char, 16> MD5::sum(const std::vector<unsigned char> &data) {
    return md5Sum(data);
}

void MD5::padding(std::vector<unsigned char> &data) {
    // Pad P bits to the initial K bits so that K + P === 448(mod 512)
    uint64_t k = data.size() * 8;
    uint64_t p = (960 - (k % 512)) % 512;
    if (p == 0) p = 512;
    //bytes count
    p /= 8;

    //Padding data is 100000....0
    data.reserve(data.size() + p + 8);
    data.push_back(0x80);
    vector<unsigned char> padData(p, 0);
    data.insert(end(data), begin(padData), end(padData));

    // Pad K mod 2^64 to data
    // Since unsigned long long(uint64_t) is 64 bits,
    // just append the content of K to the back of data
    unsigned char tail[8];
    memcpy(tail, (unsigned char*)&k, 8);
    data.insert(end(data), begin(tail), end(tail));
}


uint32_t MD5::circularLeftShift(const uint32_t data, unsigned int c) {
    const unsigned int mask = (CHAR_BIT * sizeof(data)) - 1;
    c &= mask;

    return (data << c) | (data >> ((-c) & mask));
}


// The next 4 functions are the round functions g used in HMD5.
auto F = [](uint32_t b, uint32_t c, uint32_t d) { return (b & c) | (~b & d); };
auto G = [](uint32_t b, uint32_t c, uint32_t d) { return (b & d) | (c & ~d); };
auto H = [](uint32_t b, uint32_t c, uint32_t d) { return b ^ c ^ d; };
auto I = [](uint32_t b, uint32_t c, uint32_t d) { return c ^ (b | ~d); };

// output a 128-bit data from input of 512-bit message data
// and 128-bit cv data.
std::array<unsigned char, 16> MD5::HMD5(const array<unsigned char, 64> &data,
                                        const array<unsigned char, 16> &cv) {
    array<function<uint32_t(uint32_t, uint32_t, uint32_t)>, 4> g = {F, G, H, I};

    uint32_t a, b, c, d, prev_a, prev_b, prev_c, prev_d;
    memcpy(&a, &cv.data()[0], 4);
    prev_a = a;
    memcpy(&b, &cv.data()[4], 4);
    prev_b = b;
    memcpy(&c, &cv.data()[8], 4);
    prev_c = c;
    memcpy(&d, &cv.data()[12], 4);
    prev_d = d;

    int iter_num = 0;
    // 4 rounds
    for (int i = 0; i < 4; i++) {
        //16 iterations
        for (int k = 0; k < 16; k++, iter_num++) {
            auto xkIndex = x_table[iter_num];
            uint32_t xk;
            memcpy(&xk, &data[xkIndex * 4], 4);
            a = b + circularLeftShift(a + g[i](b, c, d) + xk + t_table[iter_num],
                    s_table[iter_num]);
            uint32_t aTemp = a;
            a = d;
            d = c;
            c = b;
            b = aTemp;
        }
    }
    a += prev_a;
    b += prev_b;
    c += prev_c;
    d += prev_d;

    array<unsigned char, 16> result{};

    memcpy(&result.data()[0], &a, 4);
    memcpy(&result.data()[4], &b, 4);
    memcpy(&result.data()[8], &c, 4);
    memcpy(&result.data()[12], &d, 4);

    return result;
}
