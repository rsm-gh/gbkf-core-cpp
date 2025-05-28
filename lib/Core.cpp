
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
#include <stdexcept>
#include <algorithm>
//#include <openssl/sha.h>
#include "GBKF/picosha2.hxx"
#include "GBKF/Core.hxx"

using namespace Core;


Reader::Reader(const std::vector<uint8_t>& data) {

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


Reader::Reader(const std::string& read_path) {

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
    file.read(reinterpret_cast<char*>(m_bytes_data.data()), static_cast<std::streamsize>(size));

    readSha();
    readHeader();
}


void Reader::readSha() {

    //           With OpenSSL
    //
    //m_sha256_read.assign(m_bytes_data.end() - Constants::SHA256_LENGTH, m_bytes_data.end());
    //m_sha256_calculated.resize(Constants::SHA256_LENGTH);
    //SHA256(m_bytes_data.data(), m_bytes_data.size() - Constants::SHA256_LENGTH, m_sha256_calculated.data());


    //           With PicoSha2
    //
    m_sha256_read.assign(m_bytes_data.end() - Constants::SHA256_LENGTH, m_bytes_data.end());
    m_sha256_calculated.resize(Constants::SHA256_LENGTH);
    picosha2::hash256(m_bytes_data.begin(), m_bytes_data.end() - Constants::SHA256_LENGTH, m_sha256_calculated.begin(), m_sha256_calculated.end());

}

void Reader::readHeader() {

    if (m_bytes_data.size() < Constants::Header::LENGTH) {
        throw std::invalid_argument("Header too short");
    }

    if (memcmp(m_bytes_data.data(), Constants::Header::START_KEYWORD, Constants::Header::START_KEYWORD_LENGTH) != 0) {
        throw std::invalid_argument("Invalid start keyword");
    }

    m_gbkf_version = readInt(Constants::Header::GBKF_VERSION_START, Constants::Header::GBKF_VERSION_LENGTH).first;
    m_specification_id = readInt(Constants::Header::SPECIFICATION_ID_START, Constants::Header::SPECIFICATION_LENGTH).first;
    m_specification_version = readInt(Constants::Header::SPECIFICATION_VERSION_START, Constants::Header::SPECIFICATION_VERSION_LENGTH).first;
    m_keys_length = readInt(Constants::Header::KEYS_LENGTH_START, Constants::Header::KEYS_LENGTH_LENGTH).first;
    m_keyed_values_nb = readInt(Constants::Header::KEYED_VALUES_NB_START, Constants::Header::KEYED_VALUES_NB_LENGTH).first;
}

bool Reader::verifiesSha() const {
    return m_sha256_read == m_sha256_calculated;
}

uint8_t Reader::getGbkfVersion() const {
    return m_gbkf_version;
}

uint32_t Reader::getSpecificationId() const {
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

std::pair<uint64_t, uint64_t> Reader::readInt(const uint64_t start_pos, const uint8_t length) const {
    uint64_t value = 0;
    for (int i = 0; i < length; ++i) {
        value = (value << 8) | m_bytes_data[start_pos + i];
    }
    return {value, start_pos + length};
}

std::pair<std::string, uint64_t> Reader::readAscii(const uint64_t start_pos, const uint8_t length) const {

    auto value = std::string(m_bytes_data.begin() + static_cast<std::vector<uint8_t>::difference_type>(start_pos),
                             m_bytes_data.begin() + static_cast<std::vector<uint8_t>::difference_type>(start_pos + length));

    return {value, start_pos + length};
}

std::pair<float, uint64_t> Reader::readSingle(const uint64_t start_pos) const {
    float value;
    std::memcpy(&value, m_bytes_data.data() + start_pos, Constants::SINGLE_LENGTH);
    return {value, start_pos + Constants::SINGLE_LENGTH};
}

std::pair<double, uint64_t> Reader::readDouble(const uint64_t start_pos) const {
    double value;
    std::memcpy(&value, m_bytes_data.data() + start_pos, Constants::DOUBLE_LENGTH);
    return {value, start_pos + Constants::DOUBLE_LENGTH};
}

std::pair<std::vector<uint64_t>, uint64_t> Reader::readLineInt(const uint64_t start_pos, const uint32_t values_nb) const {
    auto [integers_length, pos] = readInt(start_pos, Constants::KeyedValues::INTEGERS_LENGTH_LENGTH);
    std::vector<uint64_t> values(values_nb);
    for (uint32_t i = 0; i < values_nb; ++i) {
        std::tie(values[i], pos) = readInt(pos, integers_length);
    }
    return {values, pos};
}

std::pair<std::vector<float>, uint64_t> Reader::readLineSingle(const uint64_t start_pos, const uint32_t values_nb) const {
    std::vector<float> values(values_nb);
    uint64_t pos = start_pos;
    for (uint32_t i = 0; i < values_nb; ++i) {
        std::tie(values[i], pos) = readSingle(pos);
    }
    return {values, pos};
}

std::pair<std::vector<double>, uint64_t> Reader::readLineDouble(const uint64_t start_pos, const uint32_t values_nb) const {
    std::vector<double> values(values_nb);
    uint64_t pos = start_pos;
    for (uint32_t i = 0; i < values_nb; ++i) {
        std::tie(values[i], pos) = readDouble(pos);
    }
    return {values, pos};
}

std::unordered_map<std::string, std::vector<KeyedEntry>> Reader::getKeyedValues() const {

    std::unordered_map<std::string, std::vector<KeyedEntry>> keyed_values;

    uint64_t current_pos = Constants::Header::LENGTH;
    for (uint32_t i = 0; i < m_keyed_values_nb; ++i) {
        auto [key, p1] = readAscii(current_pos, m_keys_length);
        auto [instance_id, p2] = readInt(p1, Constants::KeyedValues::INSTANCE_ID_LENGTH);
        auto [values_nb, p3] = readInt(p2, Constants::KeyedValues::VALUES_NB_LENGTH);
        auto [value_type, p4] = readInt(p3, Constants::KeyedValues::VALUES_TYPE_LENGTH);
        current_pos = p4;

        Value value;
        value.type = static_cast<ValueType>(value_type);

        if (value.type == ValueType::INTEGER) {
            auto [values, new_pos] = readLineInt(current_pos, values_nb);
            value.integers = std::move(values);
            current_pos = new_pos;

        } else if (value.type == ValueType::SINGLE) {
            auto [values, new_pos] = readLineSingle(current_pos, values_nb);
            value.singles = std::move(values);
            current_pos = new_pos;

        } else if (value.type == ValueType::DOUBLE) {
            auto [values, new_pos] = readLineDouble(current_pos, values_nb);
            value.doubles = std::move(values);
            current_pos = new_pos;

        } else {
            throw std::runtime_error("Unsupported value type");
        }

        keyed_values[key].push_back(KeyedEntry{static_cast<uint32_t>(instance_id), value});
    }
    return keyed_values;
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
    setGbkfVersion();
    setSpecificationId();
    setSpecificationVersion();
    setKeysLength();
    setKeyedValuesNb();
}

void Writer::setGbkfVersion(const uint8_t value) {
    setInteger(value, 0, Constants::Header::GBKF_VERSION_START);
}

void Writer::setSpecificationId(const uint32_t value) {
    setInteger(value, 0, Constants::Header::SPECIFICATION_ID_START);
}

void Writer::setSpecificationVersion(const uint16_t value) {
    setInteger(value, 0, Constants::Header::SPECIFICATION_VERSION_START);
}

void Writer::setKeysLength(const uint8_t value) {
    for (const auto& key : m_keys) {
        if (key.length() != static_cast<size_t>(value)) {
            throw std::invalid_argument("Key length mismatch");
        };
    }
    setInteger(value, 1, Constants::Header::KEYS_LENGTH_START);
    m_keys_length = value;
}

void Writer::setKeyedValuesNb(const uint32_t value) {
    setInteger(value, 0, Constants::Header::KEYED_VALUES_NB_START);
}

void Writer::setKeyedValuesNbAuto() {
    setKeyedValuesNb(m_keyed_values_nb);
}

void Writer::addLineIntegers(const std::string& key,
                             const uint32_t instance_id,
                             const std::vector<uint8_t>& integers) {

    // Set the header
    std::vector<uint8_t> line_bytes = getKeyedValuesHeader(key, instance_id, integers.size(), ValueType::INTEGER);

    // Set the integer length
    line_bytes.push_back(1);

    // Set the values
    line_bytes.insert(line_bytes.end(), integers.begin(), integers.end());

    // Add to the buffer
    m_byte_buffer.insert(m_byte_buffer.end(), line_bytes.begin(), line_bytes.end());
    ++m_keyed_values_nb;

    if (std::find(m_keys.begin(), m_keys.end(), key) == m_keys.end()) {
        m_keys.push_back(key);
    }
}

void Writer::addLineIntegers(const std::string& key,
                             const uint32_t instance_id,
                             const std::vector<uint16_t>& integers) {

    // Set the header
    std::vector<uint8_t> line_bytes = getKeyedValuesHeader(key, instance_id, integers.size(), ValueType::INTEGER);

    // Set the integer length
    line_bytes.push_back(2);

    // Set the values
    for (const auto integer : integers) {
        auto integer_bytes = formatInteger(integer);
        line_bytes.insert(line_bytes.end(), integer_bytes.begin(), integer_bytes.end());
    }

    // Add to the buffer
    m_byte_buffer.insert(m_byte_buffer.end(), line_bytes.begin(), line_bytes.end());
    ++m_keyed_values_nb;

    if (std::find(m_keys.begin(), m_keys.end(), key) == m_keys.end()) {
        m_keys.push_back(key);
    }
}

void Writer::addLineIntegers(const std::string& key,
                             const uint32_t instance_id,
                             const std::vector<uint32_t>& integers) {

    // Set the header
    std::vector<uint8_t> line_bytes = getKeyedValuesHeader(key, instance_id, integers.size(), ValueType::INTEGER);

    // Set the integer length
    line_bytes.push_back(4);

    // Set the values
    for (const auto integer : integers) {
        auto integer_bytes = formatInteger(integer);
        line_bytes.insert(line_bytes.end(), integer_bytes.begin(), integer_bytes.end());
    }

    // Add to the buffer
    m_byte_buffer.insert(m_byte_buffer.end(), line_bytes.begin(), line_bytes.end());
    ++m_keyed_values_nb;

    if (std::find(m_keys.begin(), m_keys.end(), key) == m_keys.end()) {
        m_keys.push_back(key);
    }
}

void Writer::addLineIntegers(const std::string& key,
                             const uint32_t instance_id,
                             const std::vector<uint64_t>& integers) {

    // Set the header
    std::vector<uint8_t> line_bytes = getKeyedValuesHeader(key, instance_id, integers.size(), ValueType::INTEGER);

    // Set the integer length
    line_bytes.push_back(8);

    // Set the values
    for (const auto integer : integers) {
        auto integer_bytes = formatInteger(integer);
        line_bytes.insert(line_bytes.end(), integer_bytes.begin(), integer_bytes.end());
    }

    // Add to the buffer
    m_byte_buffer.insert(m_byte_buffer.end(), line_bytes.begin(), line_bytes.end());
    ++m_keyed_values_nb;

    if (std::find(m_keys.begin(), m_keys.end(), key) == m_keys.end()) {
        m_keys.push_back(key);
    }
}

void Writer::addLineSingles(const std::string& key,
                            const uint32_t instance_id,
                            const std::vector<float>& floats) {

    std::vector<uint8_t> line_bytes = getKeyedValuesHeader(key, instance_id, floats.size(), ValueType::SINGLE);

    for (auto f : floats) {
        auto d_bytes = formatSingle(f);
        line_bytes.insert(line_bytes.end(), d_bytes.begin(), d_bytes.end());
    }

    m_byte_buffer.insert(m_byte_buffer.end(), line_bytes.begin(), line_bytes.end());
    ++m_keyed_values_nb;
    if (std::find(m_keys.begin(), m_keys.end(), key) == m_keys.end()) m_keys.push_back(key);
                            }

void Writer::addLineDoubles(const std::string& key,
                            const uint32_t instance_id,
                            const std::vector<double>& doubles) {

    std::vector<uint8_t> line_bytes = getKeyedValuesHeader(key, instance_id, doubles.size(), ValueType::DOUBLE);

    for (auto d : doubles) {
        auto d_bytes = formatDouble(d);
        line_bytes.insert(line_bytes.end(), d_bytes.begin(), d_bytes.end());
    }

    m_byte_buffer.insert(m_byte_buffer.end(), line_bytes.begin(), line_bytes.end());
    ++m_keyed_values_nb;
    if (std::find(m_keys.begin(), m_keys.end(), key) == m_keys.end()) m_keys.push_back(key);
}

void Writer::write(const std::string& write_path, const bool auto_update) {

    if (auto_update) {
        setKeyedValuesNbAuto();
    }

    std::vector<uint8_t> hash(Constants::SHA256_LENGTH);
    //SHA256(m_byte_buffer.data(), m_byte_buffer.size(), hash.data());
    picosha2::hash256(m_byte_buffer.begin(), m_byte_buffer.end(), hash.begin(), hash.end());

    std::ofstream file(write_path, std::ios::binary);

    file.write(reinterpret_cast<const char*>(m_byte_buffer.data()), static_cast<std::streamsize>(m_byte_buffer.size()));
    file.write(reinterpret_cast<const char*>(hash.data()),          static_cast<std::streamsize>(hash.size()));
}

std::vector<uint8_t> Writer::formatKey(const std::string& key) {
    return {key.begin(), key.end()};
}

std::vector<uint8_t> Writer::formatInteger(uint16_t value) {
    std::vector<uint8_t> out(2);
    for (int i = 1; i >= 0; --i) {
        out[i] = static_cast<uint8_t>(value & 0xFF);
        value >>= 8;
    }
    return out;
}

std::vector<uint8_t> Writer::formatInteger(uint32_t value) {
    std::vector<uint8_t> out(4);
    for (int i = 3; i >= 0; --i) {
        out[i] = static_cast<uint8_t>(value & 0xFF);
        value >>= 8;
    }
    return out;
}

std::vector<uint8_t> Writer::formatInteger(uint64_t value) {
    std::vector<uint8_t> out(8);
    for (int i = 7; i >= 0; --i) {
        out[i] = value & 0xFF;
        value >>= 8;
    }
    return out;
}


std::vector<uint8_t> Writer::formatSingle(const float value) {

    if (value > Constants::GBKF_SINGLE_MAX) {
        throw std::invalid_argument("Single too large");
    }

    std::vector<uint8_t> out(Constants::SINGLE_LENGTH);
    std::memcpy(out.data(), &value, Constants::SINGLE_LENGTH);
    return out;
}


std::vector<uint8_t> Writer::formatDouble(const double value) {

    if (value > Constants::GBKF_DOUBLE_MAX) {
        throw std::invalid_argument("Double too large");
    }

    std::vector<uint8_t> out(Constants::DOUBLE_LENGTH);
    std::memcpy(out.data(), &value, Constants::DOUBLE_LENGTH);
    return out;
}

void Writer::setInteger(const uint8_t value,
                        const uint8_t min_value,
                        const uint64_t start_pos) {

    if (value < min_value) {
        throw std::invalid_argument("Value out of range");
    }

    std::vector<uint8_t> bytes = {value};
    std::copy(bytes.begin(), bytes.end(), m_byte_buffer.begin() + static_cast<std::vector<uint8_t>::difference_type>(start_pos));
}

void Writer::setInteger(const uint16_t value,
                        const uint16_t min_value,
                        const uint64_t start_pos) {

    if (value < min_value) {
        throw std::invalid_argument("Value out of range");
    }

    auto bytes = formatInteger(value);
    std::copy(bytes.begin(), bytes.end(), m_byte_buffer.begin() + static_cast<std::vector<uint8_t>::difference_type>(start_pos));
}

void Writer::setInteger(const uint32_t value,
                        const uint32_t min_value,
                        const uint64_t start_pos) {

    if (value < min_value) {
        throw std::invalid_argument("Value out of range");
    }

    auto bytes = formatInteger(value);
    std::copy(bytes.begin(), bytes.end(), m_byte_buffer.begin() + static_cast<std::vector<uint8_t>::difference_type>(start_pos));
}

void Writer::setInteger(const uint64_t value,
                        const uint64_t min_value,
                        const uint64_t start_pos) {

    if (value < min_value) {
        throw std::invalid_argument("Value out of range");
    }

    auto bytes = formatInteger(value);
    std::copy(bytes.begin(), bytes.end(), m_byte_buffer.begin() + static_cast<std::vector<uint8_t>::difference_type>(start_pos));
}

std::vector<uint8_t> Writer::getKeyedValuesHeader(const std::string& key,
                                                  const uint32_t instance_id,
                                                  const uint32_t values_nb,
                                                  const ValueType value_type) {

    std::vector<uint8_t> line_bytes;

    std::vector<uint8_t> key_bytes = formatKey(key);
    line_bytes.insert(line_bytes.end(), key_bytes.begin(), key_bytes.end());

    std::vector<uint8_t> id_bytes = formatInteger(instance_id);
    line_bytes.insert(line_bytes.end(), id_bytes.begin(), id_bytes.end());

    std::vector<uint8_t> count_bytes = formatInteger(values_nb);
    line_bytes.insert(line_bytes.end(), count_bytes.begin(), count_bytes.end());

    line_bytes.push_back(static_cast<uint8_t>(value_type));

    return line_bytes;
}
