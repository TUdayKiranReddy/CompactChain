/*
 * LibConversions2.cpp
 *
 *  Created on: Apr 19, 2013
 *      Author: etremel
 */

#include <iomanip>
#include <iostream>
#include <sstream>
#include <bitset>
#include <utils/LibConversions.hpp>

extern const scalar_t bn_n;

using std::dec;
using std::hex;
using std::istringstream;
using std::ostringstream;
using std::setfill;
using std::setw;
using std::string;
using std::stringstream;

namespace LibConversions {

void getModulus(flint::BigInt& modulus) {
    char buffer[1024];
    bzero(buffer, 1024);
    scalarToString(bn_n, buffer);

    modulus = flint::BigInt(buffer, 10);
}

void scalarToMpz(const scalar_t scalar, mpz_t mpz) {
    mpz_import(mpz, 4, -1, sizeof(scalar[0]), 0, 0, scalar);
}

void mpzToScalar(const mpz_t mpz, scalar_t scalar) {
    for(int i = 0; i < 4; i++) {
        memset(&scalar[i], 0, sizeof(scalar[i]));
    }
    mpz_export(scalar, NULL, -1, sizeof(scalar[0]), 0, 0, mpz);
}

void scalarToString(const scalar_t scalar, char* str) {
    mpz_t mpz;
    mpz_init(mpz);
    scalarToMpz(scalar, mpz);
    gmp_sprintf(str, "%Zd\n", mpz);
    mpz_clear(mpz);
}

void stringToScalar(const char* str, scalar_t scalar) {
    mpz_t mpz;
    mpz_init(mpz);
    gmp_sscanf(str, "%Zd\n", mpz);
    mpzToScalar(mpz, scalar);
    mpz_clear(mpz);
}

void scalarToBigMod(const scalar_t& scalar, flint::BigMod& target) {
    char buffer[1024];
    bzero(buffer, 1024);
    scalarToString(scalar, buffer);

    flint::BigInt modulus;
    getModulus(modulus);
    target.setModulus(modulus);

    target.assign(buffer);
}

void bigModToScalar(const flint::BigMod& bigmod, scalar_t& target) {
    string str = bigmod.toString();
    stringToScalar(str.c_str(), target);
}

void CryptoPPToFlint(const CryptoPP::Integer& cryptoInt, flint::BigInt& flintInt) {
    ostringstream outStream;
    outStream << cryptoInt;
    //Frustratingly, CryptoPP appends an unnecessary decimal point (".") to the
    //end of the string representation of its Integer, which prevents it from
    //being read properly by FLINT. Otherwise I could just redirect the stream.
    string intermediateString = outStream.str();
    string truncatedString = intermediateString.substr(0, intermediateString.size() - 1);
    if(!flintInt.assign(truncatedString))
        std::cerr << "Assign failed!" << std::endl;
}

void bigIntToBytes(const flint::BigInt& bigint, unsigned char* byteArray) {
    hexStringToBytes(bigint.toHex(), byteArray);
}

void bytesToBigInt(const unsigned char* byteArray, int length, flint::BigInt& bigint) {
    stringstream bytesHexString;
    bytesHexString << hex << setfill('0');
    for(int i = 0; i < length; i++) {
        bytesHexString << setw(2) << static_cast<int>(byteArray[i]);
    }
    //I don't know how to override operator>> properly to take the hex modifier, so I'll just use a constructor...
    bigint = flint::BigInt(bytesHexString.str().c_str(), 16);
}

/**
 * Helper method: ugly hack to blindly "parse" string characters
 * representing hex values by exploiting their ASCII code values.
 * @param hexDigit an ASCII character containing a digit 0-F
 * @return a byte containing its value (as binary, not ASCII), or -1 if
 *         there was an error parsing (i.e. the character was not a
 *         valid hex digit).
 */
unsigned char valueOfHex(const char& hexDigit) {
    if(hexDigit >= '0' && hexDigit <= '9') {
        return hexDigit - '0';
    }
    if(hexDigit >= 'A' && hexDigit <= 'F') {
        return hexDigit - 'A' + 10;
    }
    if(hexDigit >= 'a' && hexDigit <= 'f') {
        return hexDigit - 'a' + 10;
    }

    return -1;
}

void hexStringToBytes(const string& hexString, unsigned char* byteArray) {
    if(hexString.length() % 2 != 0) {
        //Add an implied leading 0, so the first "pair" of digits is just the lower-order one
        byteArray[0] = valueOfHex(hexString[0]);
        for(size_t i = 1; i < (hexString.length() + 1) / 2; i++) {
            byteArray[i] = valueOfHex(hexString[2 * i - 1]) * 16 + valueOfHex(hexString[2 * i]);
        }
    } else {
        for(size_t i = 0; i < hexString.length() / 2; i++) {
            byteArray[i] = valueOfHex(hexString[2 * i]) * 16 + valueOfHex(hexString[2 * i + 1]);
        }
    }
}

void hexStringToBytes(const string& hexString, std::vector<unsigned char>& byteArray) {
    if(hexString.length() % 2 != 0) {
        //Add an implied leading 0, so the first "pair" of digits is just the lower-order one
        byteArray.push_back(valueOfHex(hexString[0]));
        for(size_t i = 1; i < (hexString.length() + 1) / 2; i++) {
            byteArray.push_back(valueOfHex(hexString[2 * i - 1]) * 16 + valueOfHex(hexString[2 * i]));
        }
    } else {
        for(size_t i = 0; i < hexString.length() / 2; i++) {
            byteArray.push_back(valueOfHex(hexString[2 * i]) * 16 + valueOfHex(hexString[2 * i + 1]));
        }
    }
}

const char* hex_char_to_bin(char c)
{
    // TODO handle default / error
    switch(toupper(c))
    {
        case '0': return "0000";
        case '1': return "0001";
        case '2': return "0010";
        case '3': return "0011";
        case '4': return "0100";
        case '5': return "0101";
        case '6': return "0110";
        case '7': return "0111";
        case '8': return "1000";
        case '9': return "1001";
        case 'A': return "1010";
        case 'B': return "1011";
        case 'C': return "1100";
        case 'D': return "1101";
        case 'E': return "1110";
        case 'F': return "1111";
    }
    return "0000";
}

std::vector<unsigned char> hexStringToBits(const string& hexString){
    std::string bin;
    std::vector<unsigned char> bitArray;

    for(unsigned i = 0; i < 64; i++){
       bin += hex_char_to_bin(hexString[i]);
    }
    for (size_t i=0;i<bin.length();i++){
        bitArray.push_back(bin[i]);
    }
    return bitArray;
}
}  // namespace LibConversions
