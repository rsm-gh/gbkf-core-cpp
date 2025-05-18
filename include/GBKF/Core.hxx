
/*
    Copyright (C) 2025 Rafael Senties Martinelli. All Rights Reserved.
*/

#ifndef GBKF_CORE_HXX
#define GBKF_CORE_HXX

#include <vector>
#include <string>
#include <cstdint>
#include <unordered_map>

namespace Core {
    namespace Constants {

        constexpr int DOUBLE_LENGTH = 8;
        constexpr double GBKF_DOUBLE_MAX = 1.7976931348623157e+308;

        constexpr int SHA256_LENGTH = 32;

        namespace Header {
            constexpr const char* START_KEYWORD = "gbkf";
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

        namespace KeyedValues {
            constexpr int INSTANCE_ID_LENGTH = 4;
            constexpr int VALUES_NB_LENGTH = 4;
            constexpr int VALUES_TYPE_LENGTH = 1;
            constexpr int INTEGERS_LENGTH_LENGTH = 1;
        }
    }

    enum class ValueType {
        UNDEFINED = 0,
        INTEGER = 1,
        DOUBLE = 2
    };

    struct Value {
        ValueType type;
        std::vector<uint64_t> integers;
        std::vector<double> doubles;
    };

    struct KeyedEntry {
        uint32_t instance_id = 0;
        Value value;
    };

    class Reader {
    public:
        explicit Reader(const std::string& read_path);

        [[nodiscard]] bool verifiesSha() const;

        [[nodiscard]] uint8_t getGbkfVersion() const;
        [[nodiscard]] uint32_t getSpecificationId() const;
        [[nodiscard]] uint16_t getSpecificationVersion() const;
        [[nodiscard]] uint8_t getKeysLength() const;
        [[nodiscard]] uint32_t getKeyedValuesNb() const;

        [[nodiscard]] std::unordered_map<std::string, std::vector<KeyedEntry>> getKeyedValues() const;

    private:
        std::vector<uint8_t> m_bytes_data;
        std::vector<uint8_t> m_sha256_read;
        std::vector<uint8_t> m_sha256_calculated;

        uint8_t m_gbkf_version;
        uint32_t m_specification_id;
        uint16_t m_specification_version;
        uint8_t m_keys_length;
        uint32_t m_keyed_values_nb;

        void readHeader();

        [[nodiscard]] std::pair<uint64_t, uint64_t> readInt(uint64_t start_pos, uint8_t length) const;
        [[nodiscard]] std::pair<std::string, uint64_t> readAscii(uint64_t start_pos, uint8_t length) const;
        [[nodiscard]] std::pair<double, uint64_t> readDouble(uint64_t start_pos) const;
        [[nodiscard]] std::pair<std::vector<uint64_t>, uint64_t> readLineInt(uint64_t start_pos, uint32_t values_nb) const;
        [[nodiscard]] std::pair<std::vector<double>, uint64_t> readLineDouble(uint64_t start_pos, uint32_t values_nb) const;
    };

    class Writer {
    public:
        Writer();

        void reset();
        void setGbkfVersion(uint8_t value = 0);
        void setSpecificationId(uint32_t value = 0);
        void setSpecificationVersion(uint16_t value = 0);
        void setKeysLength(uint8_t value = 1);
        void setKeyedValuesNb(uint32_t value = 0);
        void setKeyedValuesNbAuto();

        void addLineIntegers(const std::string& key, uint32_t instance_id, const std::vector<uint8_t>& integers);
        void addLineIntegers(const std::string& key, uint32_t instance_id, const std::vector<uint16_t>& integers);
        void addLineIntegers(const std::string& key, uint32_t instance_id, const std::vector<uint32_t>& integers);
        void addLineIntegers(const std::string& key, uint32_t instance_id, const std::vector<uint64_t>& integers);
        void addLineDoubles(const std::string& key, uint32_t instance_id, const std::vector<double>& doubles);

        void write(const std::string& write_path, bool auto_update = true);

    private:
        std::vector<uint8_t> m_byte_buffer;

        uint8_t m_keys_length;
        uint32_t m_keyed_values_nb;
        std::vector<std::string> m_keys;

        static std::vector<uint8_t> formatKey(const std::string& key);

        static std::vector<uint8_t> formatInteger(uint16_t value);

        static std::vector<uint8_t> formatInteger(uint32_t value);

        static std::vector<uint8_t> formatInteger(uint64_t value);

        static std::vector<uint8_t> formatDouble(double value);
        void setInteger(uint8_t  value, uint8_t  min_value, uint64_t start_pos);
        void setInteger(uint16_t value, uint16_t min_value, uint64_t start_pos);
        void setInteger(uint32_t value, uint32_t min_value, uint64_t start_pos);
        void setInteger(uint64_t value, uint64_t min_value, uint64_t start_pos);

        static std::vector<uint8_t> getKeyedValuesHeader(const std::string& key,
                                                         uint32_t instance_id,
                                                         uint32_t values_nb,
                                                         ValueType value_type);
    };
};

#endif // GBKF_CORE_HXX