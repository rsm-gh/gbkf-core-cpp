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
#include "GBKF/GBKFCoreReader.hxx"

using namespace GBKFCore;

GBKFCoreReader::GBKFCoreReader(const std::vector<uint8_t> &data) {


    uint16_t num = 1;
    if (*reinterpret_cast<uint8_t*>(&num) != 1) {
        throw std::runtime_error("System is not little-endian. Unsupported platform.");
    }


    m_gbkf_version = 0;
    m_specification_id = 0;
    m_specification_version = 0;
    m_keys_size = 1;
    m_keyed_values_nb = 0;

    m_bytes_data = data;

    readHeader();
    readSha();

}


GBKFCoreReader::GBKFCoreReader(const std::string &read_path) {
    m_gbkf_version = 0;
    m_specification_id = 0;
    m_specification_version = 0;
    m_keys_size = 1;
    m_keyed_values_nb = 0;

    std::ifstream file(read_path, std::ios::binary);
    if (!file) {
        throw std::runtime_error("Cannot open file");
    }

    file.seekg(0, std::ios::end);
    size_t size = file.tellg();
    m_bytes_data.resize(size);
    file.seekg(0, std::ios::beg);

    // std::ifstream::read() only accepts a char* pointer as the destination buffer
    // so reinterpret_cast is used to convert the pointer of the uint8 vector.
    // This works because char and uint8_t are both 1-byte types.
    file.read(reinterpret_cast<char *>(m_bytes_data.data()), static_cast<std::streamsize>(size));

    readHeader();
    readSha();
}

bool GBKFCoreReader::verifiesSha() const {
    return m_sha256_read == m_sha256_calculated && !m_sha256_read.empty();
}

uint8_t GBKFCoreReader::getGBKFVersion() const {
    return m_gbkf_version;
}

uint32_t GBKFCoreReader::getSpecificationID() const {
    return m_specification_id;
}

uint16_t GBKFCoreReader::getSpecificationVersion() const {
    return m_specification_version;
}

uint8_t GBKFCoreReader::getKeysSize() const {
    return m_keys_size;
}

uint32_t GBKFCoreReader::getKeyedValuesNb() const {
    return m_keyed_values_nb;
}

std::unordered_map<std::string, std::vector<KeyedEntry> > GBKFCoreReader::getKeyedEntries() const {
    std::unordered_map<std::string, std::vector<KeyedEntry> > keyed_entries_mapping;

    uint64_t current_pos = Header::SIZE;

    for (uint32_t i = 0; i < m_keyed_values_nb; ++i) {
        auto [key, p1] = readString1Byte(current_pos, m_keys_size);
        auto [instance_id, p2] = readUInt32(p1);
        auto [values_nb, p3] = readUInt32(p2);
        auto [values_type, p4] = readUInt8(p3);
        current_pos = p4;

        KeyedEntry keyed_entry(static_cast<ValueType>(values_type));
        keyed_entry.instance_id = instance_id;

        switch (keyed_entry.getType()) {
            case ValueType::STRING: {

                // Read the max string size
                const auto [max_string_size, new_pos] = readUInt16(current_pos);
                current_pos = new_pos;


                if (max_string_size == 0) {
                    //
                    // Dynamic strings
                    //

                    // Read the total number of bytes
                    const auto [total_bytes, new_pos1] = readUInt32(current_pos);
                    current_pos = new_pos1;

                    std::vector<std::string> values;
                    std::tie(values, current_pos) = readValuesTextUTF8(current_pos, values_nb);

                    keyed_entry.addValues(values);

                }else {

                    //
                    // Fixed strings
                    //

                    std::vector<std::string> values;
                    std::tie(values, current_pos) = readValuesStringUTF8(current_pos, values_nb, max_string_size);

                    keyed_entry.addValues(values);
                }

                break;
            }

            case ValueType::BLOB: {
                auto [values, new_pos] = readValuesBlob(current_pos, values_nb);
                keyed_entry.addValues(values);
                current_pos = new_pos;
                break;
            }

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

void GBKFCoreReader::readSha() {

    if (m_bytes_data.size() < Header::SIZE + FOOTER_SIZE) {
        return;
    }

#ifdef USE_OPEN_SSL
    m_sha256_read.assign(m_bytes_data.end() - FOOTER_SIZE, m_bytes_data.end());
    m_sha256_calculated.resize(FOOTER_SIZE);
    SHA256(m_bytes_data.data(), m_bytes_data.size() - FOOTER_SIZE, m_sha256_calculated.data());

#else
    m_sha256_read.assign(m_bytes_data.end() - FOOTER_SIZE, m_bytes_data.end());
    m_sha256_calculated.resize(FOOTER_SIZE);
    picosha2::hash256(m_bytes_data.begin(), m_bytes_data.end() - FOOTER_SIZE, m_sha256_calculated.begin(),
                      m_sha256_calculated.end());

#endif
}

void GBKFCoreReader::readHeader() {

    if (m_bytes_data.size() < Header::SIZE) {
        throw std::runtime_error("Header too short");
    }

    if (memcmp(m_bytes_data.data(), Header::GBKF_KEYWORD, Header::GBKF_KEYWORD_SIZE) != 0) {
        throw std::invalid_argument("Invalid start keyword");
    }

    m_gbkf_version = readUInt8(Header::GBKF_VERSION_START).first;
    m_specification_id = readUInt32(Header::SPECIFICATION_ID_START).first;
    m_specification_version = readUInt16(Header::SPECIFICATION_VERSION_START).first;
    m_keys_size = readUInt8(Header::KEYS_SIZE_START).first;
    m_keyed_values_nb = readUInt32(Header::KEYED_VALUES_NB_START).first;
}

std::pair<std::string, uint64_t> GBKFCoreReader::readString1Byte(const uint64_t start_pos,
                                                                 const uint16_t max_size) const {
    const uint8_t *start_ptr = m_bytes_data.data() + start_pos;
    const uint8_t *end_ptr = start_ptr + max_size;

    const uint8_t *null_pos = std::find(start_ptr, end_ptr, '\0');

    std::string value(reinterpret_cast<const char *>(start_ptr),
                      reinterpret_cast<const char *>(null_pos));

    return {value, start_pos + max_size};
}

std::pair<std::string, uint64_t>
GBKFCoreReader::readStringUTF8(const uint64_t start_pos, const uint16_t max_size) const {
    const auto end_pos = start_pos + max_size;

    const uint8_t *start_ptr = m_bytes_data.data() + start_pos;
    const uint8_t *null_pos = std::find(start_ptr, m_bytes_data.data() + end_pos, '\0');

    std::string string(
        reinterpret_cast<const char *>(start_ptr),
        reinterpret_cast<const char *>(null_pos)
    );

    return {string, end_pos};
}

std::pair<uint8_t, uint64_t> GBKFCoreReader::readUInt8(const uint64_t start_pos) const {
    return {m_bytes_data[start_pos], start_pos + 1};
}

std::pair<uint16_t, uint64_t> GBKFCoreReader::readUInt16(const uint64_t start_pos) const {
    const auto* ptr = reinterpret_cast<const uint16_t*>(&m_bytes_data[start_pos]);
    return {*ptr, start_pos + 2};
}

std::pair<uint32_t, uint64_t> GBKFCoreReader::readUInt32(const uint64_t start_pos) const {
    const auto* ptr = reinterpret_cast<const uint32_t*>(&m_bytes_data[start_pos]);
    return {*ptr, start_pos + 4};
}

std::pair<uint64_t, uint64_t> GBKFCoreReader::readUInt64(const uint64_t start_pos) const {
    const auto* ptr = reinterpret_cast<const uint64_t*>(&m_bytes_data[start_pos]);
    return {*ptr, start_pos + 8};
}

std::pair<float, uint64_t> GBKFCoreReader::readFloat32(const uint64_t start_pos) const {
    float value;
    std::memcpy(&value, m_bytes_data.data() + start_pos, 4);
    return {value, start_pos + 4};
}

std::pair<double, uint64_t> GBKFCoreReader::readFloat64(const uint64_t start_pos) const {
    double value;
    std::memcpy(&value, m_bytes_data.data() + start_pos, 8);
    return {value, start_pos + 8};
}

std::pair<std::vector<uint8_t>, uint64_t> GBKFCoreReader::readValuesBlob(const uint64_t start_pos,
                                                                         const uint32_t values_nb) const {

    const auto it_start = std::next(m_bytes_data.cbegin(), static_cast<ptrdiff_t>(start_pos));
    const auto it_end   = std::next(it_start, static_cast<ptrdiff_t>(values_nb));

    std::vector<uint8_t> blob(it_start, it_end);

    return {blob, start_pos + values_nb};
}

std::pair<std::vector<bool>, uint64_t> GBKFCoreReader::readValuesBool(uint64_t start_pos,
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

std::pair<std::vector<std::string>, uint64_t> GBKFCoreReader::readValuesString1Byte(
    uint64_t start_pos,
    const uint32_t values_nb,
    const uint16_t max_size) const {
    std::vector<std::string> values(values_nb);

    for (uint32_t i = 0; i < values_nb; ++i) {
        std::tie(values[i], start_pos) = readString1Byte(start_pos, max_size);
    }
    return {values, start_pos};
}

std::pair<std::vector<std::string>, uint64_t> GBKFCoreReader::readValuesStringUTF8(
    uint64_t start_pos,
    const uint32_t values_nb,
    const uint16_t max_size) const {
    std::vector<std::string> values(values_nb);
    for (uint32_t i = 0; i < values_nb; ++i) {
        auto [string, new_pos] = readStringUTF8(start_pos, max_size);
        values[i] = string;
        start_pos = new_pos;
    }
    return {values, start_pos};
}

std::pair<std::vector<std::string>, uint64_t> GBKFCoreReader::readValuesText1Byte(
    const uint64_t start_pos,
    const uint32_t values_nb) const {
    std::vector<std::string> values(values_nb);

    uint64_t final_pos = start_pos;

    for (uint32_t i = 0; i < values_nb; ++i) {
        auto [string_size, new_pos] = readUInt16(final_pos);
        std::tie(values[i], final_pos) = readString1Byte(new_pos, string_size);
    }
    return {values, final_pos};
}

std::pair<std::vector<std::string>, uint64_t> GBKFCoreReader::readValuesTextUTF8(
    const uint64_t start_pos,
    const uint32_t values_nb) const {
    std::vector<std::string> values(values_nb);

    uint64_t final_pos = start_pos;

    for (uint32_t i = 0; i < values_nb; ++i) {
        auto [string_size, new_pos] = readUInt16(final_pos);
        std::tie(values[i], final_pos) = readStringUTF8(new_pos, string_size);
    }
    return {values, final_pos};
}

std::pair<std::vector<int8_t>, uint64_t> GBKFCoreReader::readValuesInt8(
    uint64_t start_pos,
    const uint32_t values_nb) const {
    std::vector<int8_t> values(values_nb);
    for (uint32_t i = 0; i < values_nb; ++i) {
        auto [value, new_pos] = readUInt8(start_pos);
        values[i] = static_cast<int8_t>(value);
        start_pos = new_pos;
    }
    return {values, start_pos};
}

std::pair<std::vector<int16_t>, uint64_t> GBKFCoreReader::readValuesInt16(
    uint64_t start_pos, const uint32_t values_nb) const {
    std::vector<int16_t> values(values_nb);
    for (uint32_t i = 0; i < values_nb; ++i) {
        auto [value, new_pos] = readUInt16(start_pos);
        values[i] = static_cast<int16_t>(value);
        start_pos = new_pos;
    }
    return {values, start_pos};
}

std::pair<std::vector<int32_t>, uint64_t> GBKFCoreReader::readValuesInt32(
    uint64_t start_pos, const uint32_t values_nb) const {
    std::vector<int32_t> values(values_nb);
    for (uint32_t i = 0; i < values_nb; ++i) {
        auto [value, new_pos] = readUInt32(start_pos);
        values[i] = static_cast<int32_t>(value);
        start_pos = new_pos;
    }
    return {values, start_pos};
}

std::pair<std::vector<int64_t>, uint64_t> GBKFCoreReader::readValuesInt64(
    uint64_t start_pos, const uint32_t values_nb) const {
    std::vector<int64_t> values(values_nb);
    for (uint32_t i = 0; i < values_nb; ++i) {
        auto [value, new_pos] = readUInt64(start_pos);
        values[i] = static_cast<int64_t>(value);
        start_pos = new_pos;
    }
    return {values, start_pos};
}

std::pair<std::vector<uint8_t>, uint64_t> GBKFCoreReader::readValuesUInt8(
    uint64_t start_pos, const uint32_t values_nb) const {
    std::vector<uint8_t> values(values_nb);
    for (uint32_t i = 0; i < values_nb; ++i) {
        std::tie(values[i], start_pos) = readUInt8(start_pos);
    }
    return {values, start_pos};
}

std::pair<std::vector<uint16_t>, uint64_t>
GBKFCoreReader::readValuesUInt16(uint64_t start_pos, const uint32_t values_nb) const {
    std::vector<uint16_t> values(values_nb);
    for (uint32_t i = 0; i < values_nb; ++i) {
        std::tie(values[i], start_pos) = readUInt16(start_pos);
    }
    return {values, start_pos};
}

std::pair<std::vector<uint32_t>, uint64_t>
GBKFCoreReader::readValuesUInt32(uint64_t start_pos, const uint32_t values_nb) const {
    std::vector<uint32_t> values(values_nb);
    for (uint32_t i = 0; i < values_nb; ++i) {
        std::tie(values[i], start_pos) = readUInt32(start_pos);
    }
    return {values, start_pos};
}

std::pair<std::vector<uint64_t>, uint64_t>
GBKFCoreReader::readValuesUInt64(uint64_t start_pos, const uint32_t values_nb) const {
    std::vector<uint64_t> values(values_nb);
    for (uint32_t i = 0; i < values_nb; ++i) {
        std::tie(values[i], start_pos) = readUInt64(start_pos);
    }
    return {values, start_pos};
}

std::pair<std::vector<float>, uint64_t> GBKFCoreReader::readValuesFloat32(const uint64_t start_pos,
                                                                          const uint32_t values_nb) const {
    std::vector<float> values(values_nb);
    uint64_t pos = start_pos;
    for (uint32_t i = 0; i < values_nb; ++i) {
        std::tie(values[i], pos) = readFloat32(pos);
    }
    return {values, pos};
}

std::pair<std::vector<double>, uint64_t> GBKFCoreReader::readValuesFloat64(const uint64_t start_pos,
                                                                           const uint32_t values_nb) const {
    std::vector<double> values(values_nb);
    uint64_t pos = start_pos;
    for (uint32_t i = 0; i < values_nb; ++i) {
        std::tie(values[i], pos) = readFloat64(pos);
    }
    return {values, pos};
}
