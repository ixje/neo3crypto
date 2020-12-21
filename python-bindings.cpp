#include <pybind11/pybind11.h>
#include "ecc.h"
#include <utility>
#include <vector>

namespace py = pybind11;
using namespace neo3crypto;

//namespace pybind11 { namespace detail {
//    template <> struct type_caster<std::vector<unsigned char>> {
//    public:
//        PYBIND11_TYPE_CASTER(std::vector<unsigned char>, _("bytes"));
//        // bytes -> std::vector<unsigned char>
//        bool load(handle src, bool) {
//            PyObject* tmp = PyBytes_FromObject(src.ptr());
//            if (!tmp)
//                return false;
//            auto size = static_cast<size_t>(PYBIND11_BYTES_SIZE(src.ptr()));
//            const auto *data = reinterpret_cast<const unsigned char *>(PYBIND11_BYTES_AS_STRING(src.ptr()));
//            value = std::move(std::vector<unsigned char>(data, data + size));
//            Py_DECREF(tmp);
//            return true;
//        }
//
//        // std::vector<unsigned char> -> bytes
//        static handle cast(std::vector<unsigned char> src, return_value_policy, handle) {
//            return py::bytes(std::string(src.begin(), src.end()));
//        }
//    };
//}}


py::bytes to_bytes(const std::vector<unsigned char>& input) {
    return py::bytes(std::string(input.begin(), input.end()));
}

PYBIND11_MODULE(neo3crypto, m) {

    m.doc() = "NEO3 cryptographic helpers";

    py::register_exception<ECCException>(m, "ECCException");

    py::enum_<ECCCURVE>(m, "ECCCurve")
            .value("SECP256R1", ECCCURVE::secp256r1)
            .value("SECP256K1", ECCCURVE::secp256k1);

    py::class_<ECPoint>(m, "ECPoint", py::multiple_inheritance())
            .def(py::init([](const py::bytes& compressed_public_key, ECCCURVE curve, bool validate) {
                return ECPoint(to_vector(compressed_public_key), curve, validate);
            }), py::arg("compressed_public_key"), py::arg("curve"), py::arg("validate"))
            .def(py::init([](const py::bytes& private_key, ECCCURVE curve) {
                return ECPoint(to_vector(private_key), curve);
            }), py::arg("private_key"), py::arg("curve"))
            .def_property_readonly("value", [](ECPoint& self) {
                return to_bytes(self.value);
            })
            .def_property_readonly("value_compressed", [](ECPoint& self) {
                return to_bytes(self.value_compressed);
            })
            .def_property_readonly("x", [](ECPoint& self) {
                auto obj = static_cast<PyObject*>(_PyLong_FromByteArray(self.value.data(),
                                                                        self.value.size() / 2,
                                                                        PY_BIG_ENDIAN,
                                                                        0) /* unsigned value*/
                                                                        );
                return py::reinterpret_steal<py::int_>(obj);
            })
            .def_property_readonly("y", [](ECPoint& self) {
                auto half = self.value.size() / 2;
                auto obj = static_cast<PyObject*>(_PyLong_FromByteArray(self.value.data() + half,
                                                                        half,
                                                                        PY_BIG_ENDIAN,
                                                                        0) /* unsigned value*/
                                                                        );
                return py::reinterpret_steal<py::int_>(obj);
            })
            .def("encode_point", [](ECPoint& self, bool compressed) {
                return to_bytes(self.encode_point(compressed));
                }, py::arg("compressed") = true)
            .def_readonly("curve", &ECPoint::curve)
            .def_property_readonly("is_infinity", &ECPoint::is_infinity)
            .def("__lt__", [](ECPoint& self, ECPoint& other) { return self < other; })
            .def("__le__", [](ECPoint& self, ECPoint& other) { return self <= other; })
            .def("__eq__", [](ECPoint& self, ECPoint& other) { return self == other; })
            .def("__gt__", [](ECPoint& self, ECPoint& other) { return self > other; })
            .def("__ge__", [](ECPoint& self, ECPoint& other) { return self >= other; });

    py::class_<KeyPair>(m, "KeyPair")
            .def(py::init([](const py::bytes& private_key, ECPoint public_key) {
                return KeyPair(to_vector(private_key), std::move(public_key));
            }), py::arg("private_key"), py::arg("public_key"))
            .def(py::init([](const py::bytes& private_key, ECCCURVE curve) {
                return KeyPair(to_vector(private_key), curve);
            }), py::arg("private_key"), py::arg("public_key"))
            .def_static("generate", &KeyPair::generate, py::arg("curve"))
            .def_property_readonly("public_key", [](KeyPair& self) { return self.public_key; })
            .def_property_readonly("private_key", [](KeyPair& self) { return to_bytes(self.private_key); });

    py::class_<ECDSA>(m, "ECDSA")
            .def(py::init<ECCCURVE, py::function>(), py::arg("curve"), py::arg("hash_func"))
            .def("sign", [](ECDSA& self, const py::bytes& private_key, const py::bytes& message) {
                auto hash_result = self.hash_func(message).attr("digest")();
                auto message_hash = to_vector(hash_result);
                return to_bytes(self.sign(to_vector(private_key), message_hash));
            }, py::arg("private_key"), py::arg("message"))
            .def("verify", [](ECDSA& self, const py::bytes& signature, const py::bytes& message, const ECPoint& public_key) {
                auto hash_result = self.hash_func(message).attr("digest")();
                auto message_hash = to_vector(hash_result);
                return self.verify(to_vector(signature), message_hash, public_key);
            }, py::arg("signature"), py::arg("message"), py::arg("public_key"));
}