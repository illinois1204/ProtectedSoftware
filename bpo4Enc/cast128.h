#pragma once
#ifndef CAST128_H
#define CAST128_H
#include <cstdint>

class CAST128 {
public:
    enum {
        KEY_LEN = 128 / 32,
        MSG_LEN = 2
    };

    typedef uint32_t Key[KEY_LEN];
    typedef uint32_t Message[MSG_LEN];

public:
    CAST128();

    void encrypt(Message msg);
    void decrypt(Message msg);

private:
    const CAST128::Key key = { 0x01234567, 0x12345678, 0x23456789, 0x3456789A };

private:
    void run(const Key key, Message msg, bool reverse = false);

private:
    typedef uint32_t SType[256];

    static const SType S1;
    static const SType S2;
    static const SType S3;
    static const SType S4;
    static const SType S5;
    static const SType S6;
    static const SType S7;
    static const SType S8;

};

#endif // CAST128_H
