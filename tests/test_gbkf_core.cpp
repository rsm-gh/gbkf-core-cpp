/*
    This file is part of gbkf-core-cpp.

 Copyright (c) 2025 Rafael Senties Martinelli.

 Licensed under the Privative-Friendly Source-Shared License (PFSSL) v1.0.
 You may use, modify, and distribute this file under the terms of that license.

 This software is provided "as is", without warranty of any kind.
 The authors are not liable for any damages arising from its use.

 See the LICENSE file for more details.
*/

#include <cassert>
#include <iostream>
#include <filesystem>
#include <limits>
#include "GBKF/GBKFCore.hxx"

void testHeader() {
    std::string path = "test_core_header.gbkf";

    struct TestEntry {
        uint8_t gbkf_version;
        uint32_t spec_id;
        uint16_t spec_version;
        uint8_t keys_length;
        uint32_t keyed_values_nb;
    };

    std::vector<TestEntry> const tests = {
        {0, 0, 0, 1, 1},
        {
            std::numeric_limits<int8_t>::max(), std::numeric_limits<int32_t>::max(),
            std::numeric_limits<int16_t>::max(), std::numeric_limits<int8_t>::max(), std::numeric_limits<int32_t>::max()
        },
        {10, 11, 12, 13, 13},
    };

    for (size_t i = 0; i < tests.size(); ++i) {
        std::string file = "test_core_header_" + std::to_string(i) + ".gbkf";
        GBKFCore::Writer writer;
        writer.setGBKFVersion(tests[i].gbkf_version);
        writer.setSpecificationId(tests[i].spec_id);
        writer.setSpecificationVersion(tests[i].spec_version);
        writer.setKeysLength(tests[i].keys_length);
        writer.setKeyedValuesNb(tests[i].keyed_values_nb);
        writer.write(file, false);

        GBKFCore::Reader reader(file);
        assert(reader.getGBKFVersion() == tests[i].gbkf_version);
        assert(reader.getSpecificationID() == tests[i].spec_id);
        assert(reader.getSpecificationVersion() == tests[i].spec_version);
        assert(reader.getKeysLength() == tests[i].keys_length);
        assert(reader.getKeyedValuesNb() == tests[i].keyed_values_nb);
        assert(reader.verifiesSha());
    }

    std::cout << "test OK > GBKFCore Header.\n";
}

void testValues() {
    std::string path = "test_core_values.gbkf";

    GBKFCore::Writer writer;
    writer.setKeysLength(2);
    std::vector<uint8_t> input_values_uint8 = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 255};
    std::vector<uint16_t> input_values_uint16 = {1, 200, 300, 400, 45, 600, 700, 800, 900, 1000};
    std::vector<uint32_t> input_values_uint32 = {100, 200, 1, 400, 500, 600, 700, 454545, 900, 1000};
    std::vector<uint64_t> input_values_uint64 = {100, 454545, 300, 400, 500, 600, 1, 800, 900, 1000};
    std::vector<float> single_values = {0, .3467846785, 6.5, 110.9, -15000.865};
    std::vector<double> double_values = {0, .3434546785, 1.5, 1000.9, -10000.865};

    writer.addKeyedValuesUInt8("IP", 1, input_values_uint8);
    writer.addKeyedValuesUInt16("IP", 2, input_values_uint16);
    writer.addKeyedValuesUInt32("IP", 3, input_values_uint32);
    writer.addKeyedValuesUInt64("IP", 4, input_values_uint64);

    writer.addKeyedValuesFloat32("SS", 5, single_values);
    writer.addKeyedValuesFloat64("DD", 1, double_values);
    writer.write(path, true);

    GBKFCore::Reader reader(path);
    auto map = reader.getKeyedEntries();

    auto output_entry_uint8 = map["IP"][0];
    assert(output_entry_uint8.instance_id == 1);
    assert(output_entry_uint8.getValues<uint8_t>(GBKFCore::ValueType::UINT8) == input_values_uint8);

    auto output_entry_uint16 = map["IP"][1];
    assert(output_entry_uint16.instance_id == 2);
    assert(output_entry_uint16.getValues<uint16_t>(GBKFCore::ValueType::UINT16) == input_values_uint16);

    auto output_entry_uint32 = map["IP"][2];
    assert(output_entry_uint32.instance_id == 3);
    assert(output_entry_uint32.getValues<uint32_t>(GBKFCore::ValueType::UINT32) == input_values_uint32);

    auto output_entry_uint64 = map["IP"][3];
    assert(output_entry_uint64.instance_id == 4);
    assert(output_entry_uint64.getValues<uint64_t>(GBKFCore::ValueType::UINT64) == input_values_uint64);

    auto ss = map["SS"][0];
    assert(ss.instance_id == 5);
    assert(ss.getType() == GBKFCore::ValueType::FLOAT32);

    std::vector<float> singles = ss.getValues<float>();
    for (size_t i = 0; i < single_values.size(); ++i) {
        assert(std::abs(singles[i] - single_values[i]) < 1e-6);
    }

    auto dd = map["DD"][0];
    assert(dd.instance_id == 1);
    assert(dd.getType() == GBKFCore::ValueType::FLOAT64);
    std::vector<double> doubles = dd.getValues<double>();
    for (size_t i = 0; i < double_values.size(); ++i) {
        assert(std::abs(doubles[i] - double_values[i]) < 1e-6);
    }

    assert(reader.verifiesSha());
    std::cout << "test OK > GBKFCore Values.\n";
}

int main() {
    try {
        testHeader();
        testValues();
    } catch (const std::exception &e) {
        std::cerr << "Test failed: " << e.what() << '\n';
        return 1;
    }
    return 0;
}
