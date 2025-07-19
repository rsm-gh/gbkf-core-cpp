/*
    This file is part of gbkf-core-cpp.

 Copyright (c) 2025 Rafael Senties Martinelli.

 Licensed under the Privative-Friendly Source-Shared License (PFSSL) v1.0.
 You may use, modify, and distribute this file under the terms of that license.

 This software is provided "as is", without warranty of any kind.
 The authors are not liable for any damages arising from its use.

 See the LICENSE file for more details.
*/

#ifndef GBKF_CORE_WRITER_HXX
#define GBKF_CORE_WRITER_HXX

#include <vector>
#include <string>
#include <cstdint>
#include "GBKF/GBKFCore.hxx"

class GBKFCoreWriter {
public:
    GBKFCoreWriter();

    void reset();

    void setStringEncoding(const std::string &encoding = GBKFCore::Constants::StringEncoding::UTF8);

    void setGBKFVersion(uint8_t value = 0);

    void setSpecificationId(uint32_t value = 0);

    void setSpecificationVersion(uint16_t value = 0);

    void setKeysSize(uint8_t value = 1);

    void setKeyedValuesNb(uint32_t value = 0);

    void setKeyedValuesNbAuto();

    void addKeyedValuesBoolean(const std::string &key, uint32_t instance_id, const std::vector<bool> &values);

    void addKeyedValuesStringASCII(const std::string &key,
                                    uint32_t instance_id,
                                    uint16_t max_size,
                                    const std::vector<std::string> &values);

    void addKeyedValuesStringLatin1(const std::string &key,
                                    uint32_t instance_id,
                                    uint16_t max_size,
                                    const std::vector<std::string> &values);

    void addKeyedValuesStringUTF8(const std::string &key, uint32_t instance_id, uint16_t max_size,
                                  const std::vector<std::string> &values);

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

    static std::string normalizeString(const std::string &input);

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
                                                     GBKFCore::ValueType value_type);
};

#endif // GBKF_CORE_WRITER_HXX
