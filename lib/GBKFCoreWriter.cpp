/*
    This file is part of gbkf-core-cpp.

 Copyright (c) 2025 Rafael Senties Martinelli.

 Licensed under the Privative-Friendly Source-Shared License (PFSSL) v1.0.
 You may use, modify, and distribute this file under the terms of that license.

 This software is provided "as is", without warranty of any kind.
 The authors are not liable for any damages arising from its use.

 See the LICENSE file for more details.
*/

#include <fstream>
#include <cstring>
#include <iostream>
#include <stdexcept>
#include <algorithm>

#ifdef USE_OPEN_SSL
    #include <openssl/sha.h>;
#else
#include "GBKF/picosha2.hxx"
#endif

#include "GBKF/GBKFCore.hxx"
#include "GBKF/GBKFCoreWriter.hxx"

using namespace GBKFCore;

GBKFCoreWriter::GBKFCoreWriter() {

    uint16_t num = 1;
    if (*reinterpret_cast<uint8_t*>(&num) != 1) {
        throw std::runtime_error("System is not little-endian. Unsupported platform.");
    }

    m_keyed_values_nb = 0;
    m_keys_size = 1;
    reset();
}

void GBKFCoreWriter::reset() {
    m_byte_buffer.assign(Header::SIZE, 0);
    std::memcpy(m_byte_buffer.data(), Header::GBKF_KEYWORD, Header::GBKF_KEYWORD_SIZE);

    m_keyed_values_nb = 0;
    m_keys.clear();
    m_keys_size = 1;

    setGBKFVersion();
    setSpecificationId();
    setSpecificationVersion();
    setMainStringEncoding();
    setSecondaryStringEncoding();
    setKeysSize();
    setKeyedValuesNb();
}

void GBKFCoreWriter::setGBKFVersion(const uint8_t value) {
    setUInt8(value, Header::GBKF_VERSION_START);
}

void GBKFCoreWriter::setSpecificationId(const uint32_t value) {
    setUInt32(value, Header::SPECIFICATION_ID_START);
}

void GBKFCoreWriter::setSpecificationVersion(const uint16_t value) {
    setUInt16(value, Header::SPECIFICATION_VERSION_START);
}

void GBKFCoreWriter::setMainStringEncoding(const EncodingType value) {
    setUInt16(static_cast<uint16_t>(value), Header::MAIN_STRING_ENCODING_START);
}

void GBKFCoreWriter::setSecondaryStringEncoding(const EncodingType value) {
    setUInt16(static_cast<uint16_t>(value), Header::SECONDARY_STRING_ENCODING_START);
}

void GBKFCoreWriter::setKeysSize(const uint8_t value) {

    if (value < 1) {
        throw std::invalid_argument("Key length can not be lower than 1");
    }

    for (const auto &key: m_keys) {
        if (key.length() != static_cast<size_t>(value)) {
            throw std::invalid_argument("Key length mismatch");
        };
    }

    setUInt8(value, Header::KEYS_SIZE_START);
    m_keys_size = value;
}

void GBKFCoreWriter::setKeyedValuesNb(const uint32_t value) {
    setUInt32(value, Header::KEYED_VALUES_NB_START);
}

void GBKFCoreWriter::setKeyedValuesNbAuto() {
    setKeyedValuesNb(m_keyed_values_nb);
}

void GBKFCoreWriter::addKeyedValuesBlob(const std::string &key,
                                         const uint32_t instance_id,
                                         const std::vector<uint8_t> &values) {
     // Add the header
     writeKeyedValuesHeader(key, instance_id, values.size(), ValueType::BLOB);

    // Add the values
    m_byte_buffer.insert(m_byte_buffer.end(), values.begin(), values.end());

    // Increment the keyed-values count
    ++m_keyed_values_nb;

    // Add the key
    if (std::find(m_keys.begin(), m_keys.end(), key) == m_keys.end()) {
        m_keys.push_back(key);
    }
}

void GBKFCoreWriter::addKeyedValuesStringASCII(const std::string &key,
                                               const uint32_t instance_id,
                                               const std::vector<std::string> &values,
                                               const uint16_t max_size,
                                               const EncodingChoice encoding_choice) {
    // Add the header
    writeKeyedValuesHeader(key, instance_id, values.size(), ValueType::STRING);

    // Add the encoding choice
    m_byte_buffer.push_back(static_cast<uint8_t>(encoding_choice));

    // Add the maximum string size  ( 0 for dynamic strings )
    const auto uint8_max_size = formatUInt16(max_size);
    m_byte_buffer.insert(m_byte_buffer.end(), uint8_max_size.begin(), uint8_max_size.end());

    // Populate the Values
    std::vector<uint8_t> values_content;

    for (const std::string &str: values) {
        auto normalized_string = normalizeString(str);

        if (max_size == 0) {

            // Set the string size
            auto string_size = formatUInt16(normalized_string.size());
            values_content.insert(values_content.end(), string_size.begin(), string_size.end());

            // Set the value
            values_content.insert(values_content.end(), normalized_string.begin(), normalized_string.end());

        }else {

            if (normalized_string.size() > max_size) {
                throw std::invalid_argument("String out of bounds");
            }

            std::vector<uint8_t> buffer(max_size, 0);
            std::copy(normalized_string.begin(), normalized_string.end(), buffer.begin());

            values_content.insert(values_content.end(), buffer.begin(), buffer.end());

        }
    }

    if (max_size == 0) {
        // Add the values bytes-size
        const auto values_bytes_size = formatUInt32(values_content.size());
        m_byte_buffer.insert(m_byte_buffer.end(), values_bytes_size.begin(), values_bytes_size.end());
    }

    // Add the values
    m_byte_buffer.insert(m_byte_buffer.end(), values_content.begin(), values_content.end());

    // Increment the keyed-values count
    ++m_keyed_values_nb;

    // Store the key
    if (std::find(m_keys.begin(), m_keys.end(), key) == m_keys.end()) {
        m_keys.push_back(key);
    }
}

void GBKFCoreWriter::addKeyedValuesStringLatin1(const std::string &key,
                                                const uint32_t instance_id,
                                                const std::vector<std::string> &values,
                                                const uint16_t max_size,
                                                const EncodingChoice encoding_choice) {

    addKeyedValuesStringASCII(key, instance_id, values, max_size, encoding_choice);
}

void GBKFCoreWriter::addKeyedValuesStringUTF8(const std::string &key,
                                              const uint32_t instance_id,
                                              const std::vector<std::string> &values,
                                              const uint16_t max_size,
                                              const EncodingChoice encoding_choice) {

    // Add the header
    writeKeyedValuesHeader(key, instance_id, values.size(), ValueType::STRING);

    // Add the encoding choice
    m_byte_buffer.push_back(static_cast<uint8_t>(encoding_choice));

    // Push the maximum string size ( 0 for dynamic strings )
    const auto uint8_max_size = formatUInt16(max_size);
    m_byte_buffer.insert(m_byte_buffer.end(), uint8_max_size.begin(), uint8_max_size.end());

    // Populate the Values
    std::vector<uint8_t> values_content;

    for (const std::string &str: values) {
        auto normalized_string = normalizeString(str);

        if (max_size == 0) {

            // Set the string size
            auto string_size = formatUInt16(normalized_string.size());
            values_content.insert(values_content.end(), string_size.begin(), string_size.end());

            // Set the value
            std::vector<uint8_t> buffer(normalized_string.size() * 4, 0); // max_size * 4 = utf-8 can use 4 bytes
            std::copy(normalized_string.begin(), normalized_string.end(), buffer.begin());

            values_content.insert(values_content.end(), buffer.begin(), buffer.end());

        }else {

            if (normalized_string.size() > max_size * 4) {
                throw std::invalid_argument("String out of bounds");
            }

            std::vector<uint8_t> buffer(max_size * 4, 0); // max_size * 4 = utf-8 can use 4 bytes
            std::copy(normalized_string.begin(), normalized_string.end(), buffer.begin());

            values_content.insert(values_content.end(), buffer.begin(), buffer.end());

        }

    }

    if (max_size == 0) {
        // Add the values bytes-size
        const auto values_bytes_size = formatUInt32(values_content.size());
        m_byte_buffer.insert(m_byte_buffer.end(), values_bytes_size.begin(), values_bytes_size.end());
    };

    // Add the values
    m_byte_buffer.insert(m_byte_buffer.end(), values_content.begin(), values_content.end());

    // Increment the keyed-values count
    ++m_keyed_values_nb;

    // Store the key
    if (std::find(m_keys.begin(), m_keys.end(), key) == m_keys.end()) {
        m_keys.push_back(key);
    }
}


void GBKFCoreWriter::addKeyedValuesBoolean(const std::string &key,
                                           const uint32_t instance_id,
                                           const std::vector<bool> &values) {
    // Add the header
    writeKeyedValuesHeader(key, instance_id, values.size(), ValueType::BOOLEAN);

    // Set the last byte number of used booleans
    uint8_t last_bools_nb = values.size() % 8;
    if (last_bools_nb == 0 && !values.empty()) {
        last_bools_nb = 8;
    }
    m_byte_buffer.push_back(last_bools_nb);

    // Pack the booleans into bytes
    std::vector<uint8_t> packed((values.size() + 7) / 8, 0); // ceil(size/8)
    for (size_t i = 0; i < values.size(); ++i) {
        if (values[i]) {
            packed[i / 8] |= (1 << (i % 8)); // LSB-first packing
        }
    }
    m_byte_buffer.insert(m_byte_buffer.end(), packed.begin(), packed.end());

    // Increment the keyed-values count
    ++m_keyed_values_nb;

    // Store the key
    if (std::find(m_keys.begin(), m_keys.end(), key) == m_keys.end()) {
        m_keys.push_back(key);
    }
}

void GBKFCoreWriter::addKeyedValuesInt8(const std::string &key,
                                        const uint32_t instance_id,
                                        const std::vector<int8_t> &values) {
    // Write header first
    writeKeyedValuesHeader(key, instance_id, static_cast<uint32_t>(values.size()), ValueType::INT8);

    // Reserve space for all values
    const size_t values_bytes = values.size() * sizeof(int8_t);
    const size_t old_size = m_byte_buffer.size();
    m_byte_buffer.resize(old_size + values_bytes);

    // Copy all values at once
    std::memcpy(m_byte_buffer.data() + old_size, values.data(), values_bytes);

    // Increment the keyed-values count
    ++m_keyed_values_nb;

    // Store the key
    if (std::find(m_keys.begin(), m_keys.end(), key) == m_keys.end()) {
        m_keys.push_back(key);
    }
}

void GBKFCoreWriter::addKeyedValuesInt16(const std::string &key,
                                         const uint32_t instance_id,
                                         const std::vector<int16_t> &values) {
    // Write header first
    writeKeyedValuesHeader(key, instance_id, static_cast<uint32_t>(values.size()), ValueType::INT16);

    // Reserve space for all values
    const size_t values_bytes = values.size() * sizeof(int16_t);
    const size_t old_size = m_byte_buffer.size();
    m_byte_buffer.resize(old_size + values_bytes);

    // Copy all values at once
    std::memcpy(m_byte_buffer.data() + old_size, values.data(), values_bytes);

    // Increment the keyed-values count
    ++m_keyed_values_nb;

    // Store the key
    if (std::find(m_keys.begin(), m_keys.end(), key) == m_keys.end()) {
        m_keys.push_back(key);
    }
}

void GBKFCoreWriter::addKeyedValuesInt32(const std::string &key,
                                         const uint32_t instance_id,
                                         const std::vector<int32_t> &values) {
    // Write header first
    writeKeyedValuesHeader(key, instance_id, static_cast<uint32_t>(values.size()), ValueType::INT32);

    // Reserve space for all values
    const size_t values_bytes = values.size() * sizeof(int32_t);
    const size_t old_size = m_byte_buffer.size();
    m_byte_buffer.resize(old_size + values_bytes);

    // Copy all values at once
    std::memcpy(m_byte_buffer.data() + old_size, values.data(), values_bytes);

    // Increment the keyed-values count
    ++m_keyed_values_nb;

    // Store the key
    if (std::find(m_keys.begin(), m_keys.end(), key) == m_keys.end()) {
        m_keys.push_back(key);
    }
}

void GBKFCoreWriter::addKeyedValuesInt64(const std::string &key,
                                         const uint32_t instance_id,
                                         const std::vector<int64_t> &values) {
    // Write header first
    writeKeyedValuesHeader(key, instance_id, static_cast<uint32_t>(values.size()), ValueType::INT64);

    // Reserve space for all values
    const size_t values_bytes = values.size() * sizeof(int64_t);
    const size_t old_size = m_byte_buffer.size();
    m_byte_buffer.resize(old_size + values_bytes);

    // Copy all values at once
    std::memcpy(m_byte_buffer.data() + old_size, values.data(), values_bytes);

    // Increment the keyed-values count
    ++m_keyed_values_nb;

    // Store the key
    if (std::find(m_keys.begin(), m_keys.end(), key) == m_keys.end()) {
        m_keys.push_back(key);
    }
}

void GBKFCoreWriter::addKeyedValuesUInt8(const std::string &key,
                                         const uint32_t instance_id,
                                         const std::vector<uint8_t> &values) {
    // Write header first
    writeKeyedValuesHeader(key, instance_id, static_cast<uint32_t>(values.size()), ValueType::UINT8);

    // Reserve space for all values
    const size_t values_bytes = values.size() * sizeof(uint8_t);
    const size_t old_size = m_byte_buffer.size();
    m_byte_buffer.resize(old_size + values_bytes);

    // Copy all values at once
    std::memcpy(m_byte_buffer.data() + old_size, values.data(), values_bytes);

    // Increment the keyed-values count
    ++m_keyed_values_nb;

    // Store the key
    if (std::find(m_keys.begin(), m_keys.end(), key) == m_keys.end()) {
        m_keys.push_back(key);
    }
}

void GBKFCoreWriter::addKeyedValuesUInt16(const std::string &key,
                                          const uint32_t instance_id,
                                          const std::vector<uint16_t> &values) {
    // Write header first
    writeKeyedValuesHeader(key, instance_id, static_cast<uint32_t>(values.size()), ValueType::UINT16);

    // Reserve space for all values
    const size_t values_bytes = values.size() * sizeof(uint16_t);
    const size_t old_size = m_byte_buffer.size();
    m_byte_buffer.resize(old_size + values_bytes);

    // Copy all values at once
    std::memcpy(m_byte_buffer.data() + old_size, values.data(), values_bytes);

    // Increment the keyed-values count
    ++m_keyed_values_nb;

    // Store the key
    if (std::find(m_keys.begin(), m_keys.end(), key) == m_keys.end()) {
        m_keys.push_back(key);
    }
}

void GBKFCoreWriter::addKeyedValuesUInt32(const std::string &key,
                                          const uint32_t instance_id,
                                          const std::vector<uint32_t> &values) {
    // Write header first
    writeKeyedValuesHeader(key, instance_id, static_cast<uint32_t>(values.size()), ValueType::UINT32);

    // Reserve space for all values
    const size_t values_bytes = values.size() * sizeof(uint32_t);
    const size_t old_size = m_byte_buffer.size();
    m_byte_buffer.resize(old_size + values_bytes);

    // Copy all values at once
    std::memcpy(m_byte_buffer.data() + old_size, values.data(), values_bytes);

    // Increment the keyed-values count
    ++m_keyed_values_nb;

    // Store the key
    if (std::find(m_keys.begin(), m_keys.end(), key) == m_keys.end()) {
        m_keys.push_back(key);
    }
}

void GBKFCoreWriter::addKeyedValuesUInt64(const std::string &key,
                                          const uint32_t instance_id,
                                          const std::vector<uint64_t> &values) {
    // Write header first
    writeKeyedValuesHeader(key, instance_id, static_cast<uint32_t>(values.size()), ValueType::UINT64);

    // Reserve space for all values
    const size_t values_bytes = values.size() * sizeof(uint64_t);
    const size_t old_size = m_byte_buffer.size();
    m_byte_buffer.resize(old_size + values_bytes);

    // Copy all values at once
    std::memcpy(m_byte_buffer.data() + old_size, values.data(), values_bytes);

    // Increment the keyed-values count
    ++m_keyed_values_nb;

    // Store the key
    if (std::find(m_keys.begin(), m_keys.end(), key) == m_keys.end()) {
        m_keys.push_back(key);
    }
}

void GBKFCoreWriter::addKeyedValuesFloat32(const std::string &key,
                                           const uint32_t instance_id,
                                           const std::vector<float> &values) {

    // Write header first
    writeKeyedValuesHeader(key, instance_id, static_cast<uint32_t>(values.size()), ValueType::FLOAT32);

    // Reserve space for all values
    const size_t values_bytes = values.size() * sizeof(float);
    const size_t old_size = m_byte_buffer.size();
    m_byte_buffer.resize(old_size + values_bytes);

    // Copy all values at once
    std::memcpy(m_byte_buffer.data() + old_size, values.data(), values_bytes);

    // Increment the keyed-values count
    ++m_keyed_values_nb;

    // Store the key
    if (std::find(m_keys.begin(), m_keys.end(), key) == m_keys.end()) {
        m_keys.push_back(key);
    }
}

void GBKFCoreWriter::addKeyedValuesFloat64(const std::string &key,
                                           const uint32_t instance_id,
                                           const std::vector<double> &values) {

    // Write header first
    writeKeyedValuesHeader(key, instance_id, static_cast<uint32_t>(values.size()), ValueType::FLOAT64);

    // Reserve space for all values
    const size_t values_bytes = values.size() * sizeof(double);
    const size_t old_size = m_byte_buffer.size();
    m_byte_buffer.resize(old_size + values_bytes);

    // Copy all values at once
    std::memcpy(m_byte_buffer.data() + old_size, values.data(), values_bytes);

    // Increment the keyed-values count
    ++m_keyed_values_nb;

    // Store the key
    if (std::find(m_keys.begin(), m_keys.end(), key) == m_keys.end()) {
        m_keys.push_back(key);
    }

};

void GBKFCoreWriter::write(const std::string &write_path,
                           const bool auto_update,
                           const bool add_footer) {
    if (auto_update) {
        setKeyedValuesNbAuto();
    }

    std::ofstream file(write_path, std::ios::binary);

    file.write(reinterpret_cast<const char *>(m_byte_buffer.data()),
               static_cast<std::streamsize>(m_byte_buffer.size()));


    if (add_footer) {
        //
        // The footer must be added by separate, or it will bug in case of multiple writes.
        //

        std::vector<uint8_t> footer_hash(FOOTER_SIZE);

#ifdef USE_OPEN_SSL
        SHA256(m_byte_buffer.data(), m_byte_buffer.size(), hash.data());
#else
        picosha2::hash256(m_byte_buffer.begin(), m_byte_buffer.end(), footer_hash.begin(), footer_hash.end());
#endif

        file.write(reinterpret_cast<const char *>(footer_hash.data()),
                   static_cast<std::streamsize>(footer_hash.size()));
    };

}

std::string GBKFCoreWriter::normalizeString(const std::string &input) {
    std::string result = input;

    // Trim trailing nulls
    auto end = result.find_last_not_of('\0');
    if (end != std::string::npos) {
        result.resize(end + 1);
    } else {
        result.clear();
    }

    return result;
}

void GBKFCoreWriter::writeKeyedValuesHeader(const std::string &key,
                                            const uint32_t instance_id,
                                            const uint32_t values_nb,
                                            ValueType value_type) {

    // Add the key
    auto key_bytes = formatKey(key);
    m_byte_buffer.insert(m_byte_buffer.end(), key_bytes.begin(), key_bytes.end());

    // Add the instance_id
    m_byte_buffer.resize(m_byte_buffer.size() + sizeof(instance_id));
    std::memcpy(m_byte_buffer.data() + m_byte_buffer.size() - sizeof(instance_id), &instance_id, sizeof(instance_id));

    // Add the values_nb
    m_byte_buffer.resize(m_byte_buffer.size() + sizeof(values_nb));
    std::memcpy(m_byte_buffer.data() + m_byte_buffer.size() - sizeof(values_nb), &values_nb, sizeof(values_nb));

    // Add value_type
    m_byte_buffer.push_back(static_cast<uint8_t>(value_type));
}

std::vector<uint8_t> GBKFCoreWriter::formatKey(const std::string &key) {
    std::string normalized_key = normalizeString(key);
    return {normalized_key.begin(), normalized_key.end()};
}

std::vector<uint8_t> GBKFCoreWriter::formatUInt16(const uint16_t value) {
    std::vector<uint8_t> out(2);
    std::memcpy(out.data(), &value, 2);
    return out;
}

std::vector<uint8_t> GBKFCoreWriter::formatUInt32(const uint32_t value) {
    std::vector<uint8_t> out(4);
    std::memcpy(out.data(), &value, 4);
    return out;
}

void GBKFCoreWriter::setUInt8(const uint8_t value,
                              const uint64_t start_pos) {
    m_byte_buffer[start_pos] = value;
}

void GBKFCoreWriter::setUInt16(const uint16_t value,
                               const uint64_t start_pos) {
    std::memcpy(m_byte_buffer.data() + start_pos, &value, sizeof(value));
}

void GBKFCoreWriter::setUInt32(const uint32_t value,
                               const uint64_t start_pos) {
    std::memcpy(m_byte_buffer.data() + start_pos, &value, sizeof(value));
}

void GBKFCoreWriter::setUInt64(const uint64_t value,
                               const uint64_t start_pos) {
    std::memcpy(m_byte_buffer.data() + start_pos, &value, sizeof(value));
}