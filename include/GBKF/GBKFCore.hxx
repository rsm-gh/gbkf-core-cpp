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
#include <optional>
#include <stdexcept>
#include <unordered_map>

namespace GBKFCore {
    namespace Constants {
        constexpr size_t FLOAT32_LENGTH = 4;
        constexpr double GBKF_FLOAT32_MAX = 3.4028235e+38f;

        constexpr size_t FLOAT62_LENGTH = 8;
        constexpr double GBKF_FLOAT62_MAX = 1.7976931348623157e+308;

        constexpr int SHA256_LENGTH = 32;

        namespace Header {
            constexpr const char *START_KEYWORD = "gbkf";
            constexpr int START_KEYWORD_LENGTH = 4;

            constexpr int GBKF_VERSION_START = START_KEYWORD_LENGTH;
            constexpr int GBKF_VERSION_LENGTH = 1;

            constexpr int SPECIFICATION_ID_START = GBKF_VERSION_START + GBKF_VERSION_LENGTH;
            constexpr int SPECIFICATION_LENGTH = 4;

            constexpr int SPECIFICATION_VERSION_START = SPECIFICATION_ID_START + SPECIFICATION_LENGTH;
            constexpr int SPECIFICATION_VERSION_LENGTH = 2;

            constexpr int KEYS_LENGTH_START = SPECIFICATION_VERSION_START + SPECIFICATION_VERSION_LENGTH;
            constexpr int KEYS_LENGTH_LENGTH = 1;

            constexpr int KEYED_VALUES_NB_START = KEYS_LENGTH_START + KEYS_LENGTH_LENGTH;
            constexpr int KEYED_VALUES_NB_LENGTH = 4;

            constexpr int LENGTH = KEYED_VALUES_NB_START + KEYED_VALUES_NB_LENGTH;
        }
    }

    enum class ValueType {
        BLOB = 0,
        BOOLEAN = 1,

        STRING = 12,
        TEXT = 13,

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
        explicit KeyedEntry(std::vector<T> initial_values);

        template<typename T>
        void addValue(const T &val);

        template<typename T>
        void addValues(const std::vector<T> &values);

        [[nodiscard]] ValueType getType() const;

        template<typename T>
        [[nodiscard]] std::vector<T> &getValues(std::optional<ValueType> expected_type = std::nullopt);

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
    std::vector<T> &KeyedEntry::getValues(const std::optional<ValueType> expected_type) {
        if (expected_type && *expected_type != m_type) {
            throw std::runtime_error("Explicit type mismatch in getValues");
        }

        ensureType<T>();
        return *static_cast<std::vector<T> *>(m_values.get());
    }

    template<typename T>
    void KeyedEntry::ensureType() const {
        if (m_type != deduceValueType<T>())
            throw std::runtime_error("Type mismatch on KeyedEntry access");
    }


    template<typename T>
    ValueType KeyedEntry::deduceValueType() {

        if constexpr (std::is_same_v<T, bool>) {
            return ValueType::BOOLEAN;

        }else if constexpr (std::is_same_v<T, int8_t>) {
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


    class Reader {
    public:
        explicit Reader(const std::string &read_path);

        explicit Reader(const std::vector<uint8_t> &data);

        [[nodiscard]] bool verifiesSha() const;

        [[nodiscard]] uint8_t getGBKFVersion() const;

        [[nodiscard]] uint32_t getSpecificationID() const;

        [[nodiscard]] uint16_t getSpecificationVersion() const;

        [[nodiscard]] uint8_t getKeysLength() const;

        [[nodiscard]] uint32_t getKeyedValuesNb() const;

        [[nodiscard]] std::unordered_map<std::string, std::vector<KeyedEntry> > getKeyedEntries() const;

    private:
        std::vector<uint8_t> m_bytes_data;
        std::vector<uint8_t> m_sha256_read;
        std::vector<uint8_t> m_sha256_calculated;

        uint8_t m_gbkf_version;
        uint32_t m_specification_id;
        uint16_t m_specification_version;
        uint8_t m_keys_length;
        uint32_t m_keyed_values_nb;

        void readSha();

        void readHeader();

        [[nodiscard]] std::pair<uint8_t, uint64_t> readUInt8(uint64_t start_pos) const;

        [[nodiscard]] std::pair<uint16_t, uint64_t> readUInt16(uint64_t start_pos) const;

        [[nodiscard]] std::pair<uint32_t, uint64_t> readUInt32(uint64_t start_pos) const;

        [[nodiscard]] std::pair<uint64_t, uint64_t> readUInt64(uint64_t start_pos) const;

        [[nodiscard]] std::pair<std::string, uint64_t> readAscii(uint64_t start_pos, uint8_t length) const;

        [[nodiscard]] std::pair<float, uint64_t> readFloat32(uint64_t start_pos) const;

        [[nodiscard]] std::pair<double, uint64_t> readFloat64(uint64_t start_pos) const;

        [[nodiscard]] std::pair<std::vector<bool>, uint64_t> readValuesBool(
            uint64_t start_pos, uint32_t values_nb, uint8_t last_byte_bools_nb) const;

        [[nodiscard]] std::pair<std::vector<int8_t>, uint64_t> readValuesInt8(
            uint64_t start_pos, uint32_t values_nb) const;

        [[nodiscard]] std::pair<std::vector<int16_t>, uint64_t> readValuesInt16(
            uint64_t start_pos, uint32_t values_nb) const;

        [[nodiscard]] std::pair<std::vector<int32_t>, uint64_t> readValuesInt32(
            uint64_t start_pos, uint32_t values_nb) const;

        [[nodiscard]] std::pair<std::vector<int64_t>, uint64_t> readValuesInt64(
            uint64_t start_pos, uint32_t values_nb) const;

        [[nodiscard]] std::pair<std::vector<uint8_t>, uint64_t> readValuesUInt8(
            uint64_t start_pos, uint32_t values_nb) const;

        [[nodiscard]] std::pair<std::vector<uint16_t>, uint64_t> readValuesUInt16(
            uint64_t start_pos, uint32_t values_nb) const;

        [[nodiscard]] std::pair<std::vector<uint32_t>, uint64_t> readValuesUInt32(
            uint64_t start_pos, uint32_t values_nb) const;

        [[nodiscard]] std::pair<std::vector<uint64_t>, uint64_t> readValuesUInt64(
            uint64_t start_pos, uint32_t values_nb) const;

        [[nodiscard]] std::pair<std::vector<float>, uint64_t> readValuesFloat32(
            uint64_t start_pos, uint32_t values_nb) const;

        [[nodiscard]] std::pair<std::vector<double>, uint64_t> readValuesFloat64(
            uint64_t start_pos, uint32_t values_nb) const;
    };

    class Writer {
    public:
        Writer();

        void reset();

        void setGBKFVersion(uint8_t value = 0);

        void setSpecificationId(uint32_t value = 0);

        void setSpecificationVersion(uint16_t value = 0);

        void setKeysLength(uint8_t value = 1);

        void setKeyedValuesNb(uint32_t value = 0);

        void setKeyedValuesNbAuto();

        void addKeyedValuesBoolean(const std::string &key, uint32_t instance_id, const std::vector<bool> &values);

        void addKeyedValuesInt8(const std::string &key, uint32_t instance_id, const std::vector<int8_t> &values);

        void addKeyedValuesInt16(const std::string &key, uint32_t instance_id, const std::vector<int16_t> &values);

        void addKeyedValuesInt32(const std::string &key, uint32_t instance_id, const std::vector<int32_t> &values);

        void addKeyedValuesInt64(const std::string &key, uint32_t instance_id, const std::vector<int64_t> &values);

        void addKeyedValuesUInt8(const std::string &key, uint32_t instance_id, const std::vector<uint8_t> &values);

        void addKeyedValuesUInt16(const std::string &key, uint32_t instance_id, const std::vector<uint16_t> &values);

        void addKeyedValuesUInt32(const std::string &key, uint32_t instance_id, const std::vector<uint32_t> &values);

        void addKeyedValuesUInt64(const std::string &key, uint32_t instance_id, const std::vector<uint64_t> &values);

        void addKeyedValuesFloat32(const std::string &key, uint32_t instance_id, const std::vector<float> &values);

        void addKeyedValuesFloat64(const std::string &key, uint32_t instance_id, const std::vector<double> &values);

        void write(const std::string &write_path, bool auto_update = true);

    private:
        std::vector<uint8_t> m_byte_buffer;

        uint8_t m_keys_length;
        uint32_t m_keyed_values_nb;
        std::vector<std::string> m_keys;

        static std::vector<uint8_t> formatKey(const std::string &key);

        static std::vector<uint8_t> formatUInt16(uint16_t value);

        static std::vector<uint8_t> formatUInt32(uint32_t value);

        static std::vector<uint8_t> formatUInt64(uint64_t value);

        static std::vector<uint8_t> formatFloat32(float value);

        static std::vector<uint8_t> formatFloat64(double value);

        void setUInt8(uint8_t value, uint8_t min_value, uint64_t start_pos);

        void setUInt16(uint16_t value, uint16_t min_value, uint64_t start_pos);

        void setUInt32(uint32_t value, uint32_t min_value, uint64_t start_pos);

        void setUInt64(uint64_t value, uint64_t min_value, uint64_t start_pos);

        static std::vector<uint8_t> getKeyedValuesHeader(const std::string &key,
                                                         uint32_t instance_id,
                                                         uint32_t values_nb,
                                                         ValueType value_type);
    };
};

#endif // GBKF_CORE_HXX
