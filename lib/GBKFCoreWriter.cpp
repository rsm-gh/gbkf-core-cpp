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
    m_keyed_values_nb = 0;
    m_keys_length = 1;
    reset();
}

void GBKFCoreWriter::reset() {
    m_byte_buffer.assign(Constants::Header::LENGTH, 0);
    std::memcpy(m_byte_buffer.data(), Constants::Header::START_KEYWORD, Constants::Header::START_KEYWORD_SIZE);
    m_keyed_values_nb = 0;
    m_keys.clear();
    m_keys_length = 1;
    setGBKFVersion();
    setSpecificationId();
    setSpecificationVersion();
    setStringEncoding();
    setKeysSize();
    setKeyedValuesNb();
}

void GBKFCoreWriter::setGBKFVersion(const uint8_t value) {
    setUInt8(value, 0, Constants::Header::GBKF_VERSION_START);
}

void GBKFCoreWriter::setSpecificationId(const uint32_t value) {
    setUInt32(value, 0, Constants::Header::SPECIFICATION_ID_START);
}

void GBKFCoreWriter::setSpecificationVersion(const uint16_t value) {
    setUInt16(value, 0, Constants::Header::SPECIFICATION_VERSION_START);
}

void GBKFCoreWriter::setStringEncoding(const std::string &encoding) {
    const std::string normalized_encoding = normalizeString(encoding);

    if (normalized_encoding.empty()) {
        throw std::invalid_argument("GBKFCoreWriter::setStringEncoding: empty string encoding");
    }

    if (normalized_encoding.size() > Constants::Header::STRING_ENCODING_SIZE) {
        throw std::invalid_argument("GBKFCoreWriter::setStringEncoding: encoding out of bounds");
    }

    std::memset(
        m_byte_buffer.data() + Constants::Header::STRING_ENCODING_START,
        0,
        Constants::Header::STRING_ENCODING_SIZE);

    std::memcpy(
        m_byte_buffer.data() + Constants::Header::STRING_ENCODING_START,
        encoding.c_str(),
        encoding.size());
}

void GBKFCoreWriter::setKeysSize(const uint8_t value) {
    for (const auto &key: m_keys) {
        if (key.length() != static_cast<size_t>(value)) {
            throw std::invalid_argument("Key length mismatch");
        };
    }
    setUInt8(value, 1, Constants::Header::KEYS_SIZE_START);
    m_keys_length = value;
}

void GBKFCoreWriter::setKeyedValuesNb(const uint32_t value) {
    setUInt32(value, 0, Constants::Header::KEYED_VALUES_NB_START);
}

void GBKFCoreWriter::setKeyedValuesNbAuto() {
    setKeyedValuesNb(m_keyed_values_nb);
}

void GBKFCoreWriter::addKeyedValuesStringASCII(const std::string &key,
                                               const uint32_t instance_id,
                                               const std::vector<std::string> &values,
                                               const uint16_t max_size) {
    // Set the header
    std::vector<uint8_t> line_bytes = getKeyedValuesHeader(key, instance_id, values.size(), ValueType::STRING);

    // Push the maximum string size
    const auto uint8_max_size = formatUInt16(max_size);
    line_bytes.insert(line_bytes.end(), uint8_max_size.begin(), uint8_max_size.end());

    // Populate the Values
    std::vector<uint8_t> values_content;

    for (const std::string &str: values) {
        auto normalized_string = normalizeString(str);

        if (max_size == 0) {

            // Set the string size
            auto string_size = formatUInt32(normalized_string.size());
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

    // Add the values bytes-size
    const auto values_bytes_size = formatUInt64(values_content.size());
    line_bytes.insert(line_bytes.end(), values_bytes_size.begin(), values_bytes_size.end());

    // Add the values
    line_bytes.insert(line_bytes.end(), values_content.begin(), values_content.end());

    // Add to the buffer
    m_byte_buffer.insert(m_byte_buffer.end(), line_bytes.begin(), line_bytes.end());
    ++m_keyed_values_nb;

    if (std::find(m_keys.begin(), m_keys.end(), key) == m_keys.end()) {
        m_keys.push_back(key);
    }
}

void GBKFCoreWriter::addKeyedValuesStringLatin1(const std::string &key,
                                                const uint32_t instance_id,
                                                const std::vector<std::string> &values,
                                                const uint16_t max_size) {
    addKeyedValuesStringASCII(key, instance_id, values, max_size);
}

void GBKFCoreWriter::addKeyedValuesStringUTF8(const std::string &key,
                                              const uint32_t instance_id,
                                              const std::vector<std::string> &values,
                                              const uint16_t max_size) {
    // Set the header
    std::vector<uint8_t> line_bytes = getKeyedValuesHeader(key, instance_id, values.size(), ValueType::STRING);

    // Push the maximum string size
    const auto uint8_max_size = formatUInt16(max_size);
    line_bytes.insert(line_bytes.end(), uint8_max_size.begin(), uint8_max_size.end());

    // Populate the Values
    std::vector<uint8_t> values_content;

    for (const std::string &str: values) {
        auto normalized_string = normalizeString(str);

        if (max_size == 0) {

            // Set the string size
            auto string_size = formatUInt32(normalized_string.size());
            values_content.insert(values_content.end(), string_size.begin(), string_size.end());

            // Set the value
            std::vector<uint8_t> buffer(normalized_string.size() * 4, 0); // max_size * 4 = utf-8 can use 4 bytes
            std::copy(normalized_string.begin(), normalized_string.end(), buffer.begin());

            values_content.insert(values_content.end(), buffer.begin(), buffer.end());

        }else {

            if (normalized_string.size() > max_size) {
                throw std::invalid_argument("String out of bounds");
            }

            std::vector<uint8_t> buffer(max_size * 4, 0); // max_size * 4 = utf-8 can use 4 bytes
            std::copy(normalized_string.begin(), normalized_string.end(), buffer.begin());

            values_content.insert(values_content.end(), buffer.begin(), buffer.end());

        }

    }

    // Add the values bytes-size
    const auto values_bytes_size = formatUInt64(values_content.size());
    line_bytes.insert(line_bytes.end(), values_bytes_size.begin(), values_bytes_size.end());

    // Add the values
    line_bytes.insert(line_bytes.end(), values_content.begin(), values_content.end());

    // Add to the buffer
    m_byte_buffer.insert(m_byte_buffer.end(), line_bytes.begin(), line_bytes.end());
    ++m_keyed_values_nb;

    if (std::find(m_keys.begin(), m_keys.end(), key) == m_keys.end()) {
        m_keys.push_back(key);
    }
}


void GBKFCoreWriter::addKeyedValuesBoolean(const std::string &key,
                                           const uint32_t instance_id,
                                           const std::vector<bool> &values) {
    // Set the header
    std::vector<uint8_t> line_bytes = getKeyedValuesHeader(key, instance_id, values.size(), ValueType::BOOLEAN);

    // Set the last byte number of used booleans
    uint8_t last_bools_nb = values.size() % 8;
    if (last_bools_nb == 0 && !values.empty()) {
        last_bools_nb = 8;
    }
    line_bytes.push_back(last_bools_nb);

    // Pack the booleans into bytes
    std::vector<uint8_t> packed((values.size() + 7) / 8, 0); // ceil(size/8)
    for (size_t i = 0; i < values.size(); ++i) {
        if (values[i]) {
            packed[i / 8] |= (1 << (i % 8)); // LSB-first packing
        }
    }
    line_bytes.insert(line_bytes.end(), packed.begin(), packed.end());

    // Add to the buffer
    m_byte_buffer.insert(m_byte_buffer.end(), line_bytes.begin(), line_bytes.end());
    ++m_keyed_values_nb;

    if (std::find(m_keys.begin(), m_keys.end(), key) == m_keys.end()) {
        m_keys.push_back(key);
    }
}

void GBKFCoreWriter::addKeyedValuesInt8(const std::string &key,
                                        const uint32_t instance_id,
                                        const std::vector<int8_t> &values) {
    // Set the header
    std::vector<uint8_t> line_bytes = getKeyedValuesHeader(key, instance_id, values.size(), ValueType::INT8);

    // Set the values
    for (const auto value: values) {
        line_bytes.push_back(static_cast<uint8_t>(value));
    }

    // Add to the buffer
    m_byte_buffer.insert(m_byte_buffer.end(), line_bytes.begin(), line_bytes.end());
    ++m_keyed_values_nb;

    if (std::find(m_keys.begin(), m_keys.end(), key) == m_keys.end()) {
        m_keys.push_back(key);
    }
}

void GBKFCoreWriter::addKeyedValuesInt16(const std::string &key,
                                         const uint32_t instance_id,
                                         const std::vector<int16_t> &values) {
    // Set the header
    std::vector<uint8_t> line_bytes = getKeyedValuesHeader(key, instance_id, values.size(), ValueType::INT16);

    // Set the values
    for (const auto value: values) {
        auto value_bytes = formatUInt16(static_cast<uint16_t>(value));
        line_bytes.insert(line_bytes.end(), value_bytes.begin(), value_bytes.end());
    }

    // Add to the buffer
    m_byte_buffer.insert(m_byte_buffer.end(), line_bytes.begin(), line_bytes.end());
    ++m_keyed_values_nb;

    if (std::find(m_keys.begin(), m_keys.end(), key) == m_keys.end()) {
        m_keys.push_back(key);
    }
}

void GBKFCoreWriter::addKeyedValuesInt32(const std::string &key,
                                         const uint32_t instance_id,
                                         const std::vector<int32_t> &values) {
    // Set the header
    std::vector<uint8_t> line_bytes = getKeyedValuesHeader(key, instance_id, values.size(), ValueType::INT32);

    // Set the values
    for (const auto value: values) {
        auto value_bytes = formatUInt32(static_cast<uint32_t>(value));
        line_bytes.insert(line_bytes.end(), value_bytes.begin(), value_bytes.end());
    }

    // Add to the buffer
    m_byte_buffer.insert(m_byte_buffer.end(), line_bytes.begin(), line_bytes.end());
    ++m_keyed_values_nb;

    if (std::find(m_keys.begin(), m_keys.end(), key) == m_keys.end()) {
        m_keys.push_back(key);
    }
}

void GBKFCoreWriter::addKeyedValuesInt64(const std::string &key,
                                         const uint32_t instance_id,
                                         const std::vector<int64_t> &values) {
    // Set the header
    std::vector<uint8_t> line_bytes = getKeyedValuesHeader(key, instance_id, values.size(), ValueType::INT64);

    // Set the values
    for (const auto value: values) {
        auto value_bytes = formatUInt64(static_cast<uint64_t>(value));
        line_bytes.insert(line_bytes.end(), value_bytes.begin(), value_bytes.end());
    }

    // Add to the buffer
    m_byte_buffer.insert(m_byte_buffer.end(), line_bytes.begin(), line_bytes.end());
    ++m_keyed_values_nb;

    if (std::find(m_keys.begin(), m_keys.end(), key) == m_keys.end()) {
        m_keys.push_back(key);
    }
}

void GBKFCoreWriter::addKeyedValuesUInt8(const std::string &key,
                                         const uint32_t instance_id,
                                         const std::vector<uint8_t> &values) {
    // Set the header
    std::vector<uint8_t> line_bytes = getKeyedValuesHeader(key, instance_id, values.size(), ValueType::UINT8);

    // Set the values
    line_bytes.insert(line_bytes.end(), values.begin(), values.end());

    // Add to the buffer
    m_byte_buffer.insert(m_byte_buffer.end(), line_bytes.begin(), line_bytes.end());
    ++m_keyed_values_nb;

    if (std::find(m_keys.begin(), m_keys.end(), key) == m_keys.end()) {
        m_keys.push_back(key);
    }
}

void GBKFCoreWriter::addKeyedValuesUInt16(const std::string &key,
                                          const uint32_t instance_id,
                                          const std::vector<uint16_t> &values) {
    // Set the header
    std::vector<uint8_t> line_bytes = getKeyedValuesHeader(key, instance_id, values.size(), ValueType::UINT16);

    // Set the values
    for (const auto value: values) {
        auto value_bytes = formatUInt16(value);
        line_bytes.insert(line_bytes.end(), value_bytes.begin(), value_bytes.end());
    }

    // Add to the buffer
    m_byte_buffer.insert(m_byte_buffer.end(), line_bytes.begin(), line_bytes.end());
    ++m_keyed_values_nb;

    if (std::find(m_keys.begin(), m_keys.end(), key) == m_keys.end()) {
        m_keys.push_back(key);
    }
}

void GBKFCoreWriter::addKeyedValuesUInt32(const std::string &key,
                                          const uint32_t instance_id,
                                          const std::vector<uint32_t> &values) {
    // Set the header
    std::vector<uint8_t> line_bytes = getKeyedValuesHeader(key, instance_id, values.size(), ValueType::UINT32);

    // Set the values
    for (const auto value: values) {
        auto value_bytes = formatUInt32(value);
        line_bytes.insert(line_bytes.end(), value_bytes.begin(), value_bytes.end());
    }

    // Add to the buffer
    m_byte_buffer.insert(m_byte_buffer.end(), line_bytes.begin(), line_bytes.end());
    ++m_keyed_values_nb;

    if (std::find(m_keys.begin(), m_keys.end(), key) == m_keys.end()) {
        m_keys.push_back(key);
    }
}

void GBKFCoreWriter::addKeyedValuesUInt64(const std::string &key,
                                          const uint32_t instance_id,
                                          const std::vector<uint64_t> &values) {
    // Set the header
    std::vector<uint8_t> line_bytes = getKeyedValuesHeader(key, instance_id, values.size(), ValueType::UINT64);

    // Set the values
    for (const auto value: values) {
        auto value_bytes = formatUInt64(value);
        line_bytes.insert(line_bytes.end(), value_bytes.begin(), value_bytes.end());
    }

    // Add to the buffer
    m_byte_buffer.insert(m_byte_buffer.end(), line_bytes.begin(), line_bytes.end());
    ++m_keyed_values_nb;

    if (std::find(m_keys.begin(), m_keys.end(), key) == m_keys.end()) {
        m_keys.push_back(key);
    }
}

void GBKFCoreWriter::addKeyedValuesFloat32(const std::string &key,
                                           const uint32_t instance_id,
                                           const std::vector<float> &values) {
    std::vector<uint8_t> line_bytes = getKeyedValuesHeader(key, instance_id, values.size(), ValueType::FLOAT32);

    for (const auto value: values) {
        auto value_bytes = formatFloat32(value);
        line_bytes.insert(line_bytes.end(), value_bytes.begin(), value_bytes.end());
    }

    m_byte_buffer.insert(m_byte_buffer.end(), line_bytes.begin(), line_bytes.end());
    ++m_keyed_values_nb;
    if (std::find(m_keys.begin(), m_keys.end(), key) == m_keys.end()) m_keys.push_back(key);
}

void GBKFCoreWriter::addKeyedValuesFloat64(const std::string &key,
                                           const uint32_t instance_id,
                                           const std::vector<double> &values) {
    std::vector<uint8_t> line_bytes = getKeyedValuesHeader(key, instance_id, values.size(), ValueType::FLOAT64);

    for (const auto value: values) {
        auto value_bytes = formatFloat64(value);
        line_bytes.insert(line_bytes.end(), value_bytes.begin(), value_bytes.end());
    }

    m_byte_buffer.insert(m_byte_buffer.end(), line_bytes.begin(), line_bytes.end());
    ++m_keyed_values_nb;
    if (std::find(m_keys.begin(), m_keys.end(), key) == m_keys.end()) m_keys.push_back(key);
}

void GBKFCoreWriter::write(const std::string &write_path, const bool auto_update) {
    if (auto_update) {
        setKeyedValuesNbAuto();
    }

    std::vector<uint8_t> hash(Constants::SHA256_SIZE);

#ifdef USE_OPEN_SSL
    SHA256(m_byte_buffer.data(), m_byte_buffer.size(), hash.data());
#else
    picosha2::hash256(m_byte_buffer.begin(), m_byte_buffer.end(), hash.begin(), hash.end());
#endif

    std::ofstream file(write_path, std::ios::binary);

    file.write(reinterpret_cast<const char *>(m_byte_buffer.data()),
               static_cast<std::streamsize>(m_byte_buffer.size()));
    file.write(reinterpret_cast<const char *>(hash.data()), static_cast<std::streamsize>(hash.size()));
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

std::vector<uint8_t> GBKFCoreWriter::getKeyedValuesHeader(const std::string &key,
                                                          const uint32_t instance_id,
                                                          const uint32_t values_nb,
                                                          const ValueType value_type) {
    std::vector<uint8_t> line_bytes;

    std::vector<uint8_t> key_bytes = formatKey(key);
    line_bytes.insert(line_bytes.end(), key_bytes.begin(), key_bytes.end());

    std::vector<uint8_t> id_bytes = formatUInt32(instance_id);
    line_bytes.insert(line_bytes.end(), id_bytes.begin(), id_bytes.end());

    std::vector<uint8_t> count_bytes = formatUInt32(values_nb);
    line_bytes.insert(line_bytes.end(), count_bytes.begin(), count_bytes.end());

    line_bytes.push_back(static_cast<uint8_t>(value_type));

    return line_bytes;
}

std::vector<uint8_t> GBKFCoreWriter::formatKey(const std::string &key) {
    std::string normalized_key = normalizeString(key);
    return {normalized_key.begin(), normalized_key.end()};
}

std::vector<uint8_t> GBKFCoreWriter::formatUInt16(uint16_t value) {
    std::vector<uint8_t> out(2);
    for (int i = 1; i >= 0; --i) {
        out[i] = static_cast<uint8_t>(value & 0xFF);
        value >>= 8;
    }
    return out;
}

std::vector<uint8_t> GBKFCoreWriter::formatUInt32(uint32_t value) {
    std::vector<uint8_t> out(4);
    for (int i = 3; i >= 0; --i) {
        out[i] = static_cast<uint8_t>(value & 0xFF);
        value >>= 8;
    }
    return out;
}

std::vector<uint8_t> GBKFCoreWriter::formatUInt64(uint64_t value) {
    std::vector<uint8_t> out(8);
    for (int i = 7; i >= 0; --i) {
        out[i] = value & 0xFF;
        value >>= 8;
    }
    return out;
}


std::vector<uint8_t> GBKFCoreWriter::formatFloat32(const float value) {
    if (value > Constants::GBKF_FLOAT32_MAX) {
        throw std::invalid_argument("Float32 too large");
    }

    std::vector<uint8_t> out(Constants::FLOAT32_SIZE);
    std::memcpy(out.data(), &value, Constants::FLOAT32_SIZE);
    return out;
}


std::vector<uint8_t> GBKFCoreWriter::formatFloat64(const double value) {
    if (value > Constants::GBKF_FLOAT62_MAX) {
        throw std::invalid_argument("Float64 too large");
    }

    std::vector<uint8_t> out(Constants::FLOAT62_SIZE);
    std::memcpy(out.data(), &value, Constants::FLOAT62_SIZE);
    return out;
}

void GBKFCoreWriter::setUInt8(const uint8_t value,
                              const uint8_t min_value,
                              const uint64_t start_pos) {
    if (value < min_value) {
        throw std::invalid_argument("Value out of range");
    }

    std::vector<uint8_t> bytes = {value};
    std::copy(bytes.begin(), bytes.end(),
              m_byte_buffer.begin() + static_cast<std::vector<uint8_t>::difference_type>(start_pos));
}

void GBKFCoreWriter::setUInt16(const uint16_t value,
                               const uint16_t min_value,
                               const uint64_t start_pos) {
    if (value < min_value) {
        throw std::invalid_argument("Value out of range");
    }

    auto bytes = formatUInt16(value);
    std::copy(bytes.begin(), bytes.end(),
              m_byte_buffer.begin() + static_cast<std::vector<uint8_t>::difference_type>(start_pos));
}

void GBKFCoreWriter::setUInt32(const uint32_t value,
                               const uint32_t min_value,
                               const uint64_t start_pos) {
    if (value < min_value) {
        throw std::invalid_argument("Value out of range");
    }

    auto bytes = formatUInt32(value);
    std::copy(bytes.begin(), bytes.end(),
              m_byte_buffer.begin() + static_cast<std::vector<uint8_t>::difference_type>(start_pos));
}

void GBKFCoreWriter::setUInt64(const uint64_t value,
                               const uint64_t min_value,
                               const uint64_t start_pos) {
    if (value < min_value) {
        throw std::invalid_argument("Value out of range");
    }

    auto bytes = formatUInt64(value);
    std::copy(bytes.begin(), bytes.end(),
              m_byte_buffer.begin() + static_cast<std::vector<uint8_t>::difference_type>(start_pos));
}
