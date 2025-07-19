/*
    This file is part of gbkf-core-cpp.

 Copyright (c) 2025 Rafael Senties Martinelli.

 Licensed under the Privative-Friendly Source-Shared License (PFSSL) v1.0.
 You may use, modify, and distribute this file under the terms of that license.

 This software is provided "as is", without warranty of any kind.
 The authors are not liable for any damages arising from its use.

 See the LICENSE file for more details.
*/

#ifndef GBKF_CORE_READER_HXX
#define GBKF_CORE_READER_HXX

#include <vector>
#include <string>
#include <cstdint>
#include <unordered_map>
#include "GBKF/GBKFCore.hxx"

class GBKFCoreReader {
public:
    explicit GBKFCoreReader(const std::string &read_path);

    explicit GBKFCoreReader(const std::vector<uint8_t> &data);

    [[nodiscard]] bool verifiesSha() const;

    [[nodiscard]] uint8_t getGBKFVersion() const;

    [[nodiscard]] uint32_t getSpecificationID() const;

    [[nodiscard]] uint16_t getSpecificationVersion() const;

    [[nodiscard]] uint8_t getKeysLength() const;

    [[nodiscard]] uint32_t getKeyedValuesNb() const;

    [[nodiscard]] std::unordered_map<std::string, std::vector<GBKFCore::KeyedEntry> > getKeyedEntries() const;

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

#endif // GBKF_CORE_READER_HXX
