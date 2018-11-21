#include <iostream>
#include <functional>
#include <string>
#include <unordered_map>
#include <sstream>
#include "md5.h"
#include "md5test.h"

using namespace std;

void print_usage() {
    cerr << "usage: md5 [-test] [-s string] [files ...]" << endl;
    exit(1);
}

int main(int argc, char** argv) {

    string inputStr;

    // Process args
    int i;
    unordered_map<string, function<void()>> processer;
    processer["s"] = [&]() {
        // md5sum a string read from command line
        if (i == argc - 1) {
            cerr << "md5: option requires an argument -- s" << endl;
            print_usage();
        } else {
            md5StrTest(argv[++i]);
        }
    };
    processer["test"] = [&]() {
        md5RunTest();
    };
    for (i = 1; i < argc; i++) {
        if (argv[i][0] != '-') break;
        string option = string(argv[i]+1);
        if (processer.count(option) != 0) {
            processer[option]();
        } else {
            cerr << "md5: illegal option -- " << option << endl;
            print_usage();
        }
    }

    //Read file
    for (; i < argc; i++) {
        md5FileTest(argv[i]);
    }

    //If no args is provided, read data from stdin
    if (argc == 1) {
        cin >> noskipws;
        stringstream dataBuf;
        dataBuf << cin.rdbuf();
        auto data = dataBuf.str();
        MD5 h;
        auto md5Data = h.sum(data);
        cout << bytesToHexStr(md5Data) << endl;
    }


    return 0;
}