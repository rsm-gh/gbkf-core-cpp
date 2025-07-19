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

using namespace GBKFCore;

Reader::Reader(const std::vector<uint8_t> &data) {
    m_gbkf_version = 0;
    m_specification_id = 0;
    m_specification_version = 0;
    m_keys_length = 1;
    m_keyed_values_nb = 0;

    m_bytes_data = data;

    if (m_bytes_data.size() < Constants::SHA256_LENGTH) {
        throw std::runtime_error("Data too small");
    }

    readSha();
    readHeader();
}


Reader::Reader(const std::string &read_path) {
    m_gbkf_version = 0;
    m_specification_id = 0;
    m_specification_version = 0;
    m_keys_length = 1;
    m_keyed_values_nb = 0;

    std::ifstream file(read_path, std::ios::binary);
    if (!file) {
        throw std::runtime_error("Cannot open file: " + read_path);
    }

    file.unsetf(std::ios::skipws);
    file.seekg(0, std::ios::end);
    size_t size = file.tellg();
    file.seekg(0, std::ios::beg);
    m_bytes_data.resize(size);
    file.read(reinterpret_cast<char *>(m_bytes_data.data()), static_cast<std::streamsize>(size));

    readSha();
    readHeader();
}

bool Reader::verifiesSha() const {
    return m_sha256_read == m_sha256_calculated;
}

uint8_t Reader::getGBKFVersion() const {
    return m_gbkf_version;
}

uint32_t Reader::getSpecificationID() const {
    return m_specification_id;
}

uint16_t Reader::getSpecificationVersion() const {
    return m_specification_version;
}

uint8_t Reader::getKeysLength() const {
    return m_keys_length;
}

uint32_t Reader::getKeyedValuesNb() const {
    return m_keyed_values_nb;
}

std::unordered_map<std::string, std::vector<KeyedEntry> > Reader::getKeyedEntries() const {
    std::unordered_map<std::string, std::vector<KeyedEntry> > keyed_entries_mapping;

    uint64_t current_pos = Constants::Header::LENGTH;

    for (uint32_t i = 0; i < m_keyed_values_nb; ++i) {
        auto [key, p1] = readAscii(current_pos, m_keys_length);
        auto [instance_id, p2] = readUInt32(p1);
        auto [values_nb, p3] = readUInt32(p2);
        auto [values_type, p4] = readUInt8(p3);
        current_pos = p4;

        KeyedEntry keyed_entry(static_cast<ValueType>(values_type));
        keyed_entry.instance_id = instance_id;

        switch (keyed_entry.getType()) {

            case ValueType::BOOLEAN: {
                auto [last_byte_bools_nb, pos1] = readUInt8(current_pos);
                auto [values, pos2] = readValuesBool(pos1, values_nb, last_byte_bools_nb);
                keyed_entry.addValues(values);
                current_pos = pos2;
                break;
            }

            case ValueType::INT8: {
                auto [values, new_pos] = readValuesInt8(current_pos, values_nb);
                keyed_entry.addValues(values);
                current_pos = new_pos;
                break;
            }

            case ValueType::INT16: {
                auto [values, new_pos] = readValuesInt16(current_pos, values_nb);
                keyed_entry.addValues(values);
                current_pos = new_pos;
                break;
            }

            case ValueType::INT32: {
                auto [values, new_pos] = readValuesInt32(current_pos, values_nb);
                keyed_entry.addValues(values);
                current_pos = new_pos;
                break;
            }

            case ValueType::INT64: {
                auto [values, new_pos] = readValuesInt64(current_pos, values_nb);
                keyed_entry.addValues(values);
                current_pos = new_pos;
                break;
            }

            case ValueType::UINT8: {
                auto [values, new_pos] = readValuesUInt8(current_pos, values_nb);
                keyed_entry.addValues(values);
                current_pos = new_pos;
                break;
            }

            case ValueType::UINT16: {
                auto [values, new_pos] = readValuesUInt16(current_pos, values_nb);
                keyed_entry.addValues(values);
                current_pos = new_pos;
                break;
            }

            case ValueType::UINT32: {
                auto [values, new_pos] = readValuesUInt32(current_pos, values_nb);
                keyed_entry.addValues(values);
                current_pos = new_pos;
                break;
            }

            case ValueType::UINT64: {
                auto [values, new_pos] = readValuesUInt64(current_pos, values_nb);
                keyed_entry.addValues(values);
                current_pos = new_pos;
                break;
            }

            case ValueType::FLOAT32: {
                auto [values, new_pos] = readValuesFloat32(current_pos, values_nb);
                keyed_entry.addValues(values);
                current_pos = new_pos;
                break;
            }

            case ValueType::FLOAT64: {
                auto [values, new_pos] = readValuesFloat64(current_pos, values_nb);
                keyed_entry.addValues(values);
                current_pos = new_pos;
                break;
            }

            default: {
                throw std::runtime_error("Unsupported value type");
            };
        }

        if (keyed_entries_mapping.find(key) != keyed_entries_mapping.end()) {
            keyed_entries_mapping[key].push_back(keyed_entry);
        } else {
            const std::vector<KeyedEntry> new_key_data = {keyed_entry};
            keyed_entries_mapping[key] = new_key_data;
        }
    }
    return keyed_entries_mapping;
}

void Reader::readSha() {
#ifdef USE_OPEN_SSL
    m_sha256_read.assign(m_bytes_data.end() - Constants::SHA256_LENGTH, m_bytes_data.end());
    m_sha256_calculated.resize(Constants::SHA256_LENGTH);
    SHA256(m_bytes_data.data(), m_bytes_data.size() - Constants::SHA256_LENGTH, m_sha256_calculated.data());

#else
    m_sha256_read.assign(m_bytes_data.end() - Constants::SHA256_LENGTH, m_bytes_data.end());
    m_sha256_calculated.resize(Constants::SHA256_LENGTH);
    picosha2::hash256(m_bytes_data.begin(), m_bytes_data.end() - Constants::SHA256_LENGTH, m_sha256_calculated.begin(),
                      m_sha256_calculated.end());

#endif
}

void Reader::readHeader() {
    if (m_bytes_data.size() < Constants::Header::LENGTH) {
        throw std::invalid_argument("Header too short");
    }

    if (memcmp(m_bytes_data.data(), Constants::Header::START_KEYWORD, Constants::Header::START_KEYWORD_LENGTH) != 0) {
        throw std::invalid_argument("Invalid start keyword");
    }

    m_gbkf_version = readUInt8(Constants::Header::GBKF_VERSION_START).first;
    m_specification_id = readUInt32(Constants::Header::SPECIFICATION_ID_START).first;
    m_specification_version = readUInt16(Constants::Header::SPECIFICATION_VERSION_START).first;
    m_keys_length = readUInt8(Constants::Header::KEYS_LENGTH_START).first;
    m_keyed_values_nb = readUInt32(Constants::Header::KEYED_VALUES_NB_START).first;
}

std::pair<uint8_t, uint64_t> Reader::readUInt8(const uint64_t start_pos) const {
    return {m_bytes_data[start_pos], start_pos + 1};
}

std::pair<uint16_t, uint64_t> Reader::readUInt16(const uint64_t start_pos) const {
    uint16_t value = (static_cast<uint16_t>(m_bytes_data[start_pos]) << 8) |
                     static_cast<uint16_t>(m_bytes_data[start_pos + 1]);
    return {value, start_pos + 2};
}

std::pair<uint32_t, uint64_t> Reader::readUInt32(const uint64_t start_pos) const {
    uint32_t value = (static_cast<uint32_t>(m_bytes_data[start_pos]) << 24) |
                     (static_cast<uint32_t>(m_bytes_data[start_pos + 1]) << 16) |
                     (static_cast<uint32_t>(m_bytes_data[start_pos + 2]) << 8) |
                     static_cast<uint32_t>(m_bytes_data[start_pos + 3]);
    return {value, start_pos + 4};
}

std::pair<uint64_t, uint64_t> Reader::readUInt64(const uint64_t start_pos) const {
    uint64_t value = 0;
    for (int i = 0; i < 8; ++i) {
        value = (value << 8) | static_cast<uint64_t>(m_bytes_data[start_pos + i]);
    }
    return {value, start_pos + 8};
}

std::pair<std::string, uint64_t> Reader::readAscii(const uint64_t start_pos, const uint8_t length) const {
    auto value = std::string(m_bytes_data.begin() + static_cast<std::vector<uint8_t>::difference_type>(start_pos),
                             m_bytes_data.begin() + static_cast<std::vector<uint8_t>::difference_type>(
                                 start_pos + length));

    return {value, start_pos + length};
}

std::pair<float, uint64_t> Reader::readFloat32(const uint64_t start_pos) const {
    float value;
    std::memcpy(&value, m_bytes_data.data() + start_pos, Constants::FLOAT32_LENGTH);
    return {value, start_pos + Constants::FLOAT32_LENGTH};
}

std::pair<double, uint64_t> Reader::readFloat64(const uint64_t start_pos) const {
    double value;
    std::memcpy(&value, m_bytes_data.data() + start_pos, Constants::FLOAT62_LENGTH);
    return {value, start_pos + Constants::FLOAT62_LENGTH};
}

std::pair<std::vector<bool>, uint64_t> Reader::readValuesBool(uint64_t start_pos,
                                                              const uint32_t values_nb,
                                                              const uint8_t last_byte_bools_nb) const {

    if (last_byte_bools_nb < 1 || last_byte_bools_nb > 8) {
        throw std::invalid_argument("Boolean reading out of bounds on last byte");
    }

    std::vector<bool> values;
    values.reserve(values_nb);

    const uint32_t bytes_nb = values_nb / 8 + (last_byte_bools_nb == 8 ? 0 : 1);

    for (uint32_t i = 0; i < bytes_nb; ++i) {
        auto [byte, new_pos] = readUInt8(start_pos);
        start_pos = new_pos;

        const uint8_t bits_to_process = (i == bytes_nb - 1) ? last_byte_bools_nb : 8;
        for (uint8_t bit = 0; bit < bits_to_process; ++bit) {
            values.push_back((byte >> bit) & 1);
        }
    }

    return {values, start_pos};
}

std::pair<std::vector<int8_t>, uint64_t> Reader::readValuesInt8(uint64_t start_pos, const uint32_t values_nb) const {
    std::vector<int8_t> values(values_nb);
    for (uint32_t i = 0; i < values_nb; ++i) {
        auto [value, new_pos] = readUInt8(start_pos);
        values[i] = static_cast<int8_t>(value);
        start_pos = new_pos;
    }
    return {values, start_pos};
}

std::pair<std::vector<int16_t>, uint64_t> Reader::readValuesInt16(uint64_t start_pos, const uint32_t values_nb) const {
    std::vector<int16_t> values(values_nb);
    for (uint32_t i = 0; i < values_nb; ++i) {
        auto [value, new_pos] = readUInt16(start_pos);
        values[i] = static_cast<int16_t>(value);
        start_pos = new_pos;
    }
    return {values, start_pos};
}

std::pair<std::vector<int32_t>, uint64_t> Reader::readValuesInt32(uint64_t start_pos, const uint32_t values_nb) const {
    std::vector<int32_t> values(values_nb);
    for (uint32_t i = 0; i < values_nb; ++i) {
        auto [value, new_pos] = readUInt32(start_pos);
        values[i] = static_cast<int32_t>(value);
        start_pos = new_pos;
    }
    return {values, start_pos};
}

std::pair<std::vector<int64_t>, uint64_t> Reader::readValuesInt64(uint64_t start_pos, const uint32_t values_nb) const {
    std::vector<int64_t> values(values_nb);
    for (uint32_t i = 0; i < values_nb; ++i) {
        auto [value, new_pos] = readUInt64(start_pos);
        values[i] = static_cast<int64_t>(value);
        start_pos = new_pos;
    }
    return {values, start_pos};
}

std::pair<std::vector<uint8_t>, uint64_t> Reader::readValuesUInt8(uint64_t start_pos, const uint32_t values_nb) const {
    std::vector<uint8_t> values(values_nb);
    for (uint32_t i = 0; i < values_nb; ++i) {
        std::tie(values[i], start_pos) = readUInt8(start_pos);
    }
    return {values, start_pos};
}

std::pair<std::vector<uint16_t>, uint64_t>
Reader::readValuesUInt16(uint64_t start_pos, const uint32_t values_nb) const {
    std::vector<uint16_t> values(values_nb);
    for (uint32_t i = 0; i < values_nb; ++i) {
        std::tie(values[i], start_pos) = readUInt16(start_pos);
    }
    return {values, start_pos};
}

std::pair<std::vector<uint32_t>, uint64_t>
Reader::readValuesUInt32(uint64_t start_pos, const uint32_t values_nb) const {
    std::vector<uint32_t> values(values_nb);
    for (uint32_t i = 0; i < values_nb; ++i) {
        std::tie(values[i], start_pos) = readUInt32(start_pos);
    }
    return {values, start_pos};
}

std::pair<std::vector<uint64_t>, uint64_t>
Reader::readValuesUInt64(uint64_t start_pos, const uint32_t values_nb) const {
    std::vector<uint64_t> values(values_nb);
    for (uint32_t i = 0; i < values_nb; ++i) {
        std::tie(values[i], start_pos) = readUInt64(start_pos);
    }
    return {values, start_pos};
}

std::pair<std::vector<float>, uint64_t> Reader::readValuesFloat32(const uint64_t start_pos,
                                                                  const uint32_t values_nb) const {
    std::vector<float> values(values_nb);
    uint64_t pos = start_pos;
    for (uint32_t i = 0; i < values_nb; ++i) {
        std::tie(values[i], pos) = readFloat32(pos);
    }
    return {values, pos};
}

std::pair<std::vector<double>, uint64_t> Reader::readValuesFloat64(const uint64_t start_pos,
                                                                   const uint32_t values_nb) const {
    std::vector<double> values(values_nb);
    uint64_t pos = start_pos;
    for (uint32_t i = 0; i < values_nb; ++i) {
        std::tie(values[i], pos) = readFloat64(pos);
    }
    return {values, pos};
}

Writer::Writer() {
    m_keyed_values_nb = 0;
    m_keys_length = 1;
    reset();
}

void Writer::reset() {
    m_byte_buffer.assign(Constants::Header::LENGTH, 0);
    std::memcpy(m_byte_buffer.data(), Constants::Header::START_KEYWORD, Constants::Header::START_KEYWORD_LENGTH);
    m_keyed_values_nb = 0;
    m_keys.clear();
    m_keys_length = 1;
    setGBKFVersion();
    setSpecificationId();
    setSpecificationVersion();
    setKeysLength();
    setKeyedValuesNb();
}

void Writer::setGBKFVersion(const uint8_t value) {
    setUInt8(value, 0, Constants::Header::GBKF_VERSION_START);
}

void Writer::setSpecificationId(const uint32_t value) {
    setUInt32(value, 0, Constants::Header::SPECIFICATION_ID_START);
}

void Writer::setSpecificationVersion(const uint16_t value) {
    setUInt16(value, 0, Constants::Header::SPECIFICATION_VERSION_START);
}

void Writer::setKeysLength(const uint8_t value) {
    for (const auto &key: m_keys) {
        if (key.length() != static_cast<size_t>(value)) {
            throw std::invalid_argument("Key length mismatch");
        };
    }
    setUInt8(value, 1, Constants::Header::KEYS_LENGTH_START);
    m_keys_length = value;
}

void Writer::setKeyedValuesNb(const uint32_t value) {
    setUInt32(value, 0, Constants::Header::KEYED_VALUES_NB_START);
}

void Writer::setKeyedValuesNbAuto() {
    setKeyedValuesNb(m_keyed_values_nb);
}

void Writer::addKeyedValuesBoolean(const std::string &key,
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

void Writer::addKeyedValuesInt8(const std::string &key,
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

void Writer::addKeyedValuesInt16(const std::string &key,
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

void Writer::addKeyedValuesInt32(const std::string &key,
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

void Writer::addKeyedValuesInt64(const std::string &key,
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

void Writer::addKeyedValuesUInt8(const std::string &key,
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

void Writer::addKeyedValuesUInt16(const std::string &key,
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

void Writer::addKeyedValuesUInt32(const std::string &key,
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

void Writer::addKeyedValuesUInt64(const std::string &key,
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

void Writer::addKeyedValuesFloat32(const std::string &key,
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

void Writer::addKeyedValuesFloat64(const std::string &key,
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

void Writer::write(const std::string &write_path, const bool auto_update) {
    if (auto_update) {
        setKeyedValuesNbAuto();
    }

    std::vector<uint8_t> hash(Constants::SHA256_LENGTH);

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


std::vector<uint8_t> Writer::getKeyedValuesHeader(const std::string &key,
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

std::vector<uint8_t> Writer::formatKey(const std::string &key) {
    return {key.begin(), key.end()};
}

std::vector<uint8_t> Writer::formatUInt16(uint16_t value) {
    std::vector<uint8_t> out(2);
    for (int i = 1; i >= 0; --i) {
        out[i] = static_cast<uint8_t>(value & 0xFF);
        value >>= 8;
    }
    return out;
}

std::vector<uint8_t> Writer::formatUInt32(uint32_t value) {
    std::vector<uint8_t> out(4);
    for (int i = 3; i >= 0; --i) {
        out[i] = static_cast<uint8_t>(value & 0xFF);
        value >>= 8;
    }
    return out;
}

std::vector<uint8_t> Writer::formatUInt64(uint64_t value) {
    std::vector<uint8_t> out(8);
    for (int i = 7; i >= 0; --i) {
        out[i] = value & 0xFF;
        value >>= 8;
    }
    return out;
}


std::vector<uint8_t> Writer::formatFloat32(const float value) {
    if (value > Constants::GBKF_FLOAT32_MAX) {
        throw std::invalid_argument("Float32 too large");
    }

    std::vector<uint8_t> out(Constants::FLOAT32_LENGTH);
    std::memcpy(out.data(), &value, Constants::FLOAT32_LENGTH);
    return out;
}


std::vector<uint8_t> Writer::formatFloat64(const double value) {
    if (value > Constants::GBKF_FLOAT62_MAX) {
        throw std::invalid_argument("Float64 too large");
    }

    std::vector<uint8_t> out(Constants::FLOAT62_LENGTH);
    std::memcpy(out.data(), &value, Constants::FLOAT62_LENGTH);
    return out;
}

void Writer::setUInt8(const uint8_t value,
                      const uint8_t min_value,
                      const uint64_t start_pos) {
    if (value < min_value) {
        throw std::invalid_argument("Value out of range");
    }

    std::vector<uint8_t> bytes = {value};
    std::copy(bytes.begin(), bytes.end(),
              m_byte_buffer.begin() + static_cast<std::vector<uint8_t>::difference_type>(start_pos));
}

void Writer::setUInt16(const uint16_t value,
                       const uint16_t min_value,
                       const uint64_t start_pos) {
    if (value < min_value) {
        throw std::invalid_argument("Value out of range");
    }

    auto bytes = formatUInt16(value);
    std::copy(bytes.begin(), bytes.end(),
              m_byte_buffer.begin() + static_cast<std::vector<uint8_t>::difference_type>(start_pos));
}

void Writer::setUInt32(const uint32_t value,
                       const uint32_t min_value,
                       const uint64_t start_pos) {
    if (value < min_value) {
        throw std::invalid_argument("Value out of range");
    }

    auto bytes = formatUInt32(value);
    std::copy(bytes.begin(), bytes.end(),
              m_byte_buffer.begin() + static_cast<std::vector<uint8_t>::difference_type>(start_pos));
}

void Writer::setUInt64(const uint64_t value,
                       const uint64_t min_value,
                       const uint64_t start_pos) {
    if (value < min_value) {
        throw std::invalid_argument("Value out of range");
    }

    auto bytes = formatUInt64(value);
    std::copy(bytes.begin(), bytes.end(),
              m_byte_buffer.begin() + static_cast<std::vector<uint8_t>::difference_type>(start_pos));
}
