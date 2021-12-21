#include <vector>
#include <stdio.h>
#include <iostream>
#include <fstream>
#include <windows.h>
#include "cast128.h"

int seek_label(std::vector<unsigned char> data, int label, int offset)
{
    for (unsigned int i = offset; i < data.size() - 5; i++)
        if (
            data[i] == 0xb8
            && data[i + 1] == label
            && data[i + 2] == label
            && data[i + 3] == label
            && data[i + 4] == label
            )
            return i;
    return -1;
}

int main(int argc, char** argv)
{
    CAST128 cast128;
    std::vector<unsigned char> data(100240);
    const char* fileName = argc > 1 ? argv[1] : "bpo4.exe";
    std::ifstream ifn(fileName, std::ios::binary);

    if (!ifn) {
        printf("Can't open file bpo4.exe");
        exit(-1);
    }

    ifn.seekg(0, std::ios::end);
    int fileSize = ifn.tellg();
    data.resize(fileSize);
    ifn.seekg(0, std::ios::beg);
    ifn.read((char*)&data[0], fileSize);

    int start_of_function = seek_label(data, 0x11, 0) + 5;
    int end_of_function = seek_label(data, 0x22, start_of_function);
    int length_of_function = end_of_function - start_of_function;

    for (int i = 0; i < length_of_function; i += 2 * sizeof(DWORD)) {
        CAST128::Message buff = { *(DWORD*)&data[start_of_function + i], *(DWORD*)&data[start_of_function + i + sizeof(DWORD)] };
        cast128.encrypt(buff);
        memcpy(&data[start_of_function + i], &buff, sizeof(buff));
    }

    std::ofstream ofn("bpo4_encrypted.exe", std::fstream::binary);
    ofn.write(reinterpret_cast<const char*>(&data[0]), data.size() * sizeof(char));
    return 0;
}