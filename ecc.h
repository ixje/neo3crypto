#pragma once
#include <utility>
#include <vector>
#include <string>
#include <exception>
#include <unordered_map>
#include "microecc/uECC.h"
#include <pybind11/pybind11.h>

namespace neo3crypto {
    class ECCException: public std::exception {
    private:
        std::string _message;
    public:
        explicit ECCException(std::string  message) : _message(std::move(message)) {};
        const char* what() const noexcept override {
            return _message.c_str();
        }
    };

    enum class ECCCURVE : unsigned char {
        secp256r1 = 0x0,
        secp256k1 = 0x1
    };

    class ECPoint {
    public:
        ECPoint() = default;
        ECPoint(std::vector<unsigned char> compressed_public_key, ECCCURVE curve, bool validate);
        ECPoint(const std::vector<unsigned char>& private_key, ECCCURVE curve);
        /* public_key should not have the 0x04 prefix
         * public_key_compressed should have 0x02 or 0x03 prefix
         * */
        ECPoint(std::vector<unsigned char> public_key, std::vector<unsigned char> public_key_compressed, ECCCURVE curve) :
                value{std::move(public_key)}, value_compressed{std::move(public_key_compressed)}, curve{curve} {}

        std::vector<unsigned char> encode_point(bool compressed = true);
        std::vector<unsigned char> value;
        std::vector<unsigned char> value_compressed;
        ECCCURVE curve = ECCCURVE::secp256r1;

        friend bool operator<(const ECPoint& lhs, const ECPoint& rhs) { return lhs.compare_to(rhs) < 0; }

        friend bool operator>(const ECPoint& lhs, const ECPoint& rhs) { return rhs < lhs; }

        friend bool operator<=(const ECPoint& lhs, const ECPoint& rhs) { return !(lhs > rhs); }

        friend bool operator>=(const ECPoint& lhs, const ECPoint& rhs) { return !(lhs < rhs); }

        friend bool operator==(const ECPoint& lhs, const ECPoint& rhs) { return lhs.compare_to(rhs) == 0; }

        friend bool operator!=(const ECPoint& lhs, const ECPoint& rhs) { return lhs.compare_to(rhs) != 0; }

        bool is_infinity() { return _is_infinity; }
    private:
        int compare_to(const ECPoint& other) const;
        bool _is_infinity = false;
    };

    class KeyPair {
    public:
        KeyPair(std::vector<unsigned char> private_key_, ECPoint public_key_) :
            private_key{std::move(private_key_)}, public_key{std::move(public_key_)} {};
        KeyPair(std::vector<unsigned char> private_key_, ECCCURVE curve) :
            private_key{std::move(private_key_)}, public_key{ECPoint(private_key, curve)} {};

        static KeyPair generate(ECCCURVE curve);
        std::vector<unsigned char> private_key;
        ECPoint public_key;
    };

    std::vector<unsigned char> to_vector(const pybind11::bytes& input);

    class ECDSA {
    public:
        ECDSA(ECCCURVE curve_, pybind11::function hash_func_) : curve{curve_}, hash_func{std::move(hash_func_)} {};
        [[nodiscard]] std::vector<unsigned char> sign(const std::vector<unsigned char>& private_key, const std::vector<unsigned char>& message_hash) const;
        bool verify(const std::vector<unsigned char>& signature, const std::vector<unsigned char>& message_hash, ECPoint public_key);
        ECCCURVE curve;
        pybind11::function hash_func;
    };
    }