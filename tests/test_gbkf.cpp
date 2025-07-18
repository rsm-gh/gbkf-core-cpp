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
#include "GBKF/GBKFCoreReader.hxx"
#include "GBKF/GBKFCoreWriter.hxx"

void testHeader() {
    std::string path = "test_core_header.gbkf";

    struct TestEntry {
        uint8_t gbkf_version;
        uint32_t spec_id;
        uint16_t spec_version;
        std::string str_encoding;
        uint8_t keys_length;
        uint32_t keyed_values_nb;
    };

    std::vector<TestEntry> const tests = {
        {0, 0, 0, "UTF-8", 1, 1},
        {
            std::numeric_limits<int8_t>::max(),
            std::numeric_limits<int32_t>::max(),
            std::numeric_limits<int16_t>::max(),
            "16_________chars",
            std::numeric_limits<int8_t>::max(),
            std::numeric_limits<int32_t>::max()
        },
        {10, 11, 12, "ASCII",13, 13},
    };

    for (size_t i = 0; i < tests.size(); ++i) {
        std::string file = "test_core_header_" + std::to_string(i) + ".gbkf";
        GBKFCoreWriter writer;

        const TestEntry& test_entry = tests[i];

        writer.setGBKFVersion(test_entry.gbkf_version);
        writer.setSpecificationId(test_entry.spec_id);
        writer.setSpecificationVersion(test_entry.spec_version);
        writer.setStringEncoding(test_entry.str_encoding);
        writer.setKeysSize(test_entry.keys_length);
        writer.setKeyedValuesNb(test_entry.keyed_values_nb);
        writer.write(file, false);

        GBKFCoreReader reader(file);
        assert(reader.getGBKFVersion() == test_entry.gbkf_version);
        assert(reader.getSpecificationID() == test_entry.spec_id);
        assert(reader.getSpecificationVersion() == test_entry.spec_version);

        auto encoding = reader.getStringEncoding();
        auto str_enc = test_entry.str_encoding;
        assert(reader.getStringEncoding() == test_entry.str_encoding);
        assert(reader.getKeysSize() == test_entry.keys_length);
        assert(reader.getKeyedValuesNb() == test_entry.keyed_values_nb);
        assert(reader.verifiesSha());
    }

    std::cout << "test OK > GBKFCore Header.\n";
}

void testKeyedValues(const std::string &encoding) {
    std::string path = "test_core_values.gbkf";

    std::vector<uint8_t> input_values_uint8 = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 255};
    std::vector<uint16_t> input_values_uint16 = {1, 200, 300, 400, 45, 600, 700, 800, 900, 1000};
    std::vector<uint32_t> input_values_uint32 = {100, 200, 1, 400, 500, 600, 700, 454545, 900, 1000};
    std::vector<uint64_t> input_values_uint64 = {100, 454545, 300, 400, 500, 600, 1, 800, 900, 1000};

    std::vector<int8_t> input_values_int8 = {-1, 2, 3, 4, -5, 6, 7, 8, 9, 10, 100};
    std::vector<int16_t> input_values_int16 = {1, 200, -300, 400, 45, -600, 700, 800, 900, 1000};
    std::vector<int32_t> input_values_int32 = {100, 200, 1, 400, 500, -600, 700, 454545, -900, 1000};
    std::vector<int64_t> input_values_int64 = {100, -454545, 300, 400, 500, 600, 1, 800, -900, 1000};

    std::vector<std::string> input_strings;
    std::vector<std::string> input_texts;

    if (encoding == GBKFCore::Constants::StringEncoding::ASCII) {
        input_strings = {"A","B","HELLO","TEST"};
        input_texts = {"A","BB","CCC","DDDD"};

    }else if (encoding == GBKFCore::Constants::StringEncoding::LATIN1) {
        input_strings = {"A","¢","Ñ","HELLO","TEST"};
        input_texts = {"A","BB","¢¢¢","ÑÑÑÑ"};

    }else {
        // examples with 1, 2, 3, 4 bytes
        input_strings = {"A","é","€","𐍈"};
        input_texts = {"A","éé","€€€","𐍈𐍈𐍈𐍈𐍈"};
    };

    std::vector<bool> input_booleans = {true, true, true, true, false, false, false, false, true, false};
    std::vector<float> input_floats32 = {0, .3467846785, 6.5, 110.9, -15000.865};
    std::vector<double> input_floats64 = {0, .3434546785, 1.5, 1000.9, -10000.865};


    //
    // WRITER
    //

    GBKFCoreWriter writer;
    writer.setKeysSize(2);
    writer.setStringEncoding(encoding);

    writer.addKeyedValuesUInt8("UI", 1, input_values_uint8);
    writer.addKeyedValuesUInt16("UI", 2, input_values_uint16);
    writer.addKeyedValuesUInt32("UI", 3, input_values_uint32);
    writer.addKeyedValuesUInt64("UI", 4, input_values_uint64);

    writer.addKeyedValuesInt8("SI", 1, input_values_int8);
    writer.addKeyedValuesInt16("SI", 2, input_values_int16);
    writer.addKeyedValuesInt32("SI", 3, input_values_int32);
    writer.addKeyedValuesInt64("SI", 4, input_values_int64);

    if (encoding == GBKFCore::Constants::StringEncoding::ASCII) {
        writer.addKeyedValuesStringASCII("ST", 1, input_strings, 6);
        writer.addKeyedValuesStringASCII("TT", 1, input_texts);

    }else if (encoding == GBKFCore::Constants::StringEncoding::LATIN1) {
        writer.addKeyedValuesStringLatin1("ST", 1, input_strings, 6);
        writer.addKeyedValuesStringLatin1("TT", 1, input_texts);

    }else {
        writer.addKeyedValuesStringUTF8("ST", 1, input_strings, 6);
        writer.addKeyedValuesStringUTF8("TT", 1, input_texts);
    };

    writer.addKeyedValuesBoolean("BO", 1, input_booleans);
    writer.addKeyedValuesFloat32("F3", 5, input_floats32);
    writer.addKeyedValuesFloat64("F6", 1, input_floats64);

    writer.write(path, true);


    //
    // READER
    //

    GBKFCoreReader reader(path);
    auto map = reader.getKeyedEntries();

    auto output_entry_uint8 = map["UI"][0];
    assert(output_entry_uint8.instance_id == 1);
    assert(output_entry_uint8.getValues<uint8_t>() == input_values_uint8);

    auto output_entry_uint16 = map["UI"][1];
    assert(output_entry_uint16.instance_id == 2);
    assert(output_entry_uint16.getValues<uint16_t>() == input_values_uint16);

    auto output_entry_uint32 = map["UI"][2];
    assert(output_entry_uint32.instance_id == 3);
    assert(output_entry_uint32.getValues<uint32_t>() == input_values_uint32);

    auto output_entry_uint64 = map["UI"][3];
    assert(output_entry_uint64.instance_id == 4);
    assert(output_entry_uint64.getValues<uint64_t>() == input_values_uint64);

    auto output_entry_int8 = map["SI"][0];
    assert(output_entry_int8.instance_id == 1);
    assert(output_entry_int8.getValues<int8_t>() == input_values_int8);

    auto output_entry_int16 = map["SI"][1];
    assert(output_entry_int16.instance_id == 2);
    assert(output_entry_int16.getValues<int16_t>() == input_values_int16);

    auto output_entry_int32 = map["SI"][2];
    assert(output_entry_int32.instance_id == 3);
    assert(output_entry_int32.getValues<int32_t>() == input_values_int32);

    auto output_entry_int64 = map["SI"][3];
    assert(output_entry_int64.instance_id == 4);
    assert(output_entry_int64.getValues<int64_t>() == input_values_int64);

    auto output_entry_boolean = map["BO"][0];
    assert(output_entry_boolean.instance_id == 1);
    std::vector<bool> output_booleans = output_entry_boolean.getValues<bool>();
    for (size_t i = 0; i < input_booleans.size(); ++i) {
        assert(output_booleans[i] == input_booleans[i]);
    }

    auto output_entry_strings = map["ST"][0];
    assert(output_entry_strings.instance_id == 1);
    std::vector<std::string> output_strings = output_entry_strings.getValues<std::string>();
    for (size_t i = 0; i < input_strings.size(); ++i) {
        assert(output_strings[i] == input_strings[i]);
    }

    auto output_entry_texts = map["TT"][0];
    assert(output_entry_texts.instance_id == 1);
    std::vector<std::string> output_texts = output_entry_texts.getValues<std::string>();
    for (size_t i = 0; i < input_texts.size(); ++i) {
        assert(output_texts[i] == input_texts[i]);
    }

    auto output_entry_float32 = map["F3"][0];
    assert(output_entry_float32.instance_id == 5);
    std::vector<float> output_floats32 = output_entry_float32.getValues<float>();
    for (size_t i = 0; i < input_floats32.size(); ++i) {
        assert(std::abs(output_floats32[i] - input_floats32[i]) < 1e-6);
    }

    auto output_entry_float64 = map["F6"][0];
    assert(output_entry_float64.instance_id == 1);
    std::vector<double> output_floats64 = output_entry_float64.getValues<double>();
    for (size_t i = 0; i < input_floats64.size(); ++i) {
        assert(std::abs(output_floats64[i] - input_floats64[i]) < 1e-6);
    }

    assert(reader.verifiesSha());
    std::cout << "test OK > GBKFCore Values "+encoding+" \n";
}

int main() {
    testHeader();
    testKeyedValues(GBKFCore::Constants::StringEncoding::ASCII);
    testKeyedValues(GBKFCore::Constants::StringEncoding::LATIN1);
    testKeyedValues(GBKFCore::Constants::StringEncoding::UTF8);
    return 0;
}
