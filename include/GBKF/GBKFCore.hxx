/*
    This file is part of gbkf-core-cpp.

 Copyright (c) 2025 Rafael Senties Martinelli.

 Licensed under the Privative-Friendly Source-Shared License (PFSSL) v1.0.
 You may use, modify, and distribute this file under the terms of that license.

 This software is provided "as is", without warranty of any kind.
 The authors are not liable for any damages arising from its use.

 See the LICENSE file for more details.
*/

#ifndef GBKF_CORE_HXX
#define GBKF_CORE_HXX

#include <vector>
#include <string>
#include <cstdint>
#include <memory>
#include <stdexcept>

namespace GBKFCore {
    namespace Constants {
        constexpr size_t FLOAT32_SIZE = 4;
        constexpr double GBKF_FLOAT32_MAX = 3.4028235e+38f;

        constexpr size_t FLOAT62_SIZE = 8;
        constexpr double GBKF_FLOAT62_MAX = 1.7976931348623157e+308;

        constexpr int SHA256_SIZE = 32;

        namespace StringEncoding {
            constexpr const char *ASCII = "ASCII";
            constexpr const char *LATIN1 = "LATIN-1";
            constexpr const char *UTF8 = "UTF-8";
        }

        namespace Header {
            constexpr const char *START_KEYWORD = "gbkf";
            constexpr int START_KEYWORD_SIZE = 4;

            constexpr int GBKF_VERSION_START = START_KEYWORD_SIZE;
            constexpr int GBKF_VERSION_SIZE = 1;

            constexpr int SPECIFICATION_ID_START = GBKF_VERSION_START + GBKF_VERSION_SIZE;
            constexpr int SPECIFICATION_SIZE = 4;

            constexpr int SPECIFICATION_VERSION_START = SPECIFICATION_ID_START + SPECIFICATION_SIZE;
            constexpr int SPECIFICATION_VERSION_SIZE = 2;

            constexpr int MAIN_STRING_ENCODING_START = SPECIFICATION_VERSION_START + SPECIFICATION_VERSION_SIZE;
            constexpr int MAIN_STRING_ENCODING_SIZE = 16;

            constexpr int SECONDARY_STRING_ENCODING_START = MAIN_STRING_ENCODING_START + MAIN_STRING_ENCODING_SIZE;
            constexpr int SECONDARY_STRING_ENCODING_SIZE = 16;

            constexpr int KEYS_SIZE_START = SECONDARY_STRING_ENCODING_START + SECONDARY_STRING_ENCODING_SIZE;
            constexpr int KEYS_SIZE_SIZE = 1;

            constexpr int KEYED_VALUES_NB_START = KEYS_SIZE_START + KEYS_SIZE_SIZE;
            constexpr int KEYED_VALUES_NB_SIZE = 4;

            constexpr int LENGTH = KEYED_VALUES_NB_START + KEYED_VALUES_NB_SIZE;
        }
    }

    enum class ValueType {
        BLOB = 1,
        BOOLEAN = 2,

        STRING = 10,

        INT8 = 20,
        INT32 = 21,
        INT16 = 22,
        INT64 = 23,

        UINT8 = 30,
        UINT16 = 31,
        UINT32 = 33,
        UINT64 = 34,

        FLOAT32 = 40,
        FLOAT64 = 41,
    };

    enum class EncodingChoice {
        MAIN = 0,
        SECONDARY = 1,
    };

    class KeyedEntry {
    public:
        uint32_t instance_id = 0;

        explicit KeyedEntry(ValueType type);

        template<typename T>
        explicit KeyedEntry(std::vector<T> initial_values);

        template<typename T>
        void addValue(const T &val);

        template<typename T>
        void addValues(const std::vector<T> &values);

        [[nodiscard]] ValueType getType() const;

        template<typename T>
        [[nodiscard]] std::vector<T> &getValues();

    private:
        ValueType m_type;
        std::shared_ptr<void> m_values;

        template<typename T>
        static ValueType deduceValueType();

        template<typename T>
        void ensureType() const;
    };

    inline KeyedEntry::KeyedEntry(const ValueType type) : m_type(type) {
        switch (type) {
            case ValueType::STRING:
                m_values = std::make_shared<std::vector<std::string> >();
                break;

            case ValueType::BOOLEAN:
                m_values = std::make_shared<std::vector<bool> >();
                break;

            case ValueType::INT8:
                m_values = std::make_shared<std::vector<int8_t> >();
                break;

            case ValueType::INT16:
                m_values = std::make_shared<std::vector<int16_t> >();
                break;

            case ValueType::INT32:
                m_values = std::make_shared<std::vector<int32_t> >();
                break;

            case ValueType::INT64:
                m_values = std::make_shared<std::vector<int64_t> >();
                break;

            case ValueType::UINT8:
                m_values = std::make_shared<std::vector<uint8_t> >();
                break;

            case ValueType::UINT16:
                m_values = std::make_shared<std::vector<uint16_t> >();
                break;

            case ValueType::UINT32:
                m_values = std::make_shared<std::vector<uint32_t> >();
                break;

            case ValueType::UINT64:
                m_values = std::make_shared<std::vector<uint64_t> >();
                break;

            case ValueType::FLOAT32:
                m_values = std::make_shared<std::vector<float> >();
                break;

            case ValueType::FLOAT64:
                m_values = std::make_shared<std::vector<double> >();
                break;

            default:
                throw std::invalid_argument("Unsupported type");
        }
    }

    template<typename T>
    KeyedEntry::KeyedEntry(std::vector<T> initial_values)
        : m_type(deduceValueType<T>()), m_values(std::make_shared<std::vector<T> >(std::move(initial_values))) {
    }

    template<typename T>
    void KeyedEntry::addValue(const T &val) {
        ensureType<T>();
        getValues<T>()->push_back(val);
    }

    template<typename T>
    void KeyedEntry::addValues(const std::vector<T> &values) {
        ensureType<T>();
        auto &vec = getValues<T>();
        vec.insert(vec.end(), values.begin(), values.end());
    }

    inline ValueType KeyedEntry::getType() const {
        return m_type;
    }

    template<typename T>
    std::vector<T> &KeyedEntry::getValues() {
        ensureType<T>();
        return *static_cast<std::vector<T> *>(m_values.get());
    }

    template<typename T>
    void KeyedEntry::ensureType() const {
        if (m_type != deduceValueType<T>()) {
            throw std::runtime_error("Type mismatch on KeyedEntry access");
        }
    }


    template<typename T>
    ValueType KeyedEntry::deduceValueType() {
        if constexpr (std::is_same_v<T, bool>) {
            return ValueType::BOOLEAN;
        } else if constexpr (std::is_same_v<T, std::string>) {
            return ValueType::STRING;
        } else if constexpr (std::is_same_v<T, int8_t>) {
            return ValueType::INT8;
        } else if constexpr (std::is_same_v<T, int16_t>) {
            return ValueType::INT16;
        } else if constexpr (std::is_same_v<T, int32_t>) {
            return ValueType::INT32;
        } else if constexpr (std::is_same_v<T, int64_t>) {
            return ValueType::INT64;
        } else if constexpr (std::is_same_v<T, uint8_t>) {
            return ValueType::UINT8;
        } else if constexpr (std::is_same_v<T, uint16_t>) {
            return ValueType::UINT16;
        } else if constexpr (std::is_same_v<T, uint32_t>) {
            return ValueType::UINT32;
        } else if constexpr (std::is_same_v<T, uint64_t>) {
            return ValueType::UINT64;
        } else if constexpr (std::is_same_v<T, float>) {
            return ValueType::FLOAT32;
        } else if constexpr (std::is_same_v<T, double>) {
            return ValueType::FLOAT64;
        } else {
            throw std::invalid_argument("Unsupported type");
        }
    }
};

#endif // GBKF_CORE_HXX
