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

    namespace Header {
        constexpr const char *GBKF_KEYWORD = "gbkf";
        constexpr uint8_t GBKF_KEYWORD_SIZE = 4;

        constexpr uint8_t GBKF_VERSION_START = GBKF_KEYWORD_SIZE;
        constexpr uint8_t GBKF_VERSION_SIZE = 1;

        constexpr uint8_t SPECIFICATION_ID_START = GBKF_VERSION_START + GBKF_VERSION_SIZE;
        constexpr uint8_t SPECIFICATION_SIZE = 4;

        constexpr uint8_t SPECIFICATION_VERSION_START = SPECIFICATION_ID_START + SPECIFICATION_SIZE;
        constexpr uint8_t SPECIFICATION_VERSION_SIZE = 2;

        constexpr uint8_t KEYS_SIZE_START = SPECIFICATION_VERSION_START + SPECIFICATION_VERSION_SIZE;
        constexpr uint8_t KEYS_SIZE_SIZE = 1;

        constexpr uint8_t KEYED_VALUES_NB_START = KEYS_SIZE_START + KEYS_SIZE_SIZE;
        constexpr uint8_t KEYED_VALUES_NB_SIZE = 4;

        constexpr uint8_t SIZE = KEYED_VALUES_NB_START + KEYED_VALUES_NB_SIZE;
    }

    constexpr uint8_t FOOTER_SIZE = 32;

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

    class KeyedEntry {
    public:
        uint32_t instance_id = 0;

        explicit KeyedEntry(ValueType type);

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

            case ValueType::BLOB:
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
        if (const ValueType deduced_type = deduceValueType<T>();
            m_type != deduced_type &&
            (m_type != ValueType::BLOB && deduced_type != ValueType::UINT8)) {
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
            // Also used for BLOB
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
