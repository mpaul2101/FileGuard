#include "file_type.hpp"

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace {

bool starts_with(const std::vector<std::uint8_t>& data, const std::initializer_list<std::uint8_t>& signature) {
    if (data.size() < signature.size()) {
        return false;
    }

    std::size_t i = 0;
    for (auto byte : signature) {
        if (data[i++] != byte) {
            return false;
        }
    }
    return true;
}

}  // namespace

std::string detect_file_type(const std::vector<std::uint8_t>& header) {
    if (starts_with(header, {0x25, 0x50, 0x44, 0x46, 0x2D})) {
        return "PDF";
    }
    if (starts_with(header, {0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A})) {
        return "PNG";
    }
    if (starts_with(header, {0xFF, 0xD8, 0xFF})) {
        return "JPEG";
    }
    if (starts_with(header, {0x50, 0x4B, 0x03, 0x04}) || starts_with(header, {0x50, 0x4B, 0x05, 0x06}) ||
        starts_with(header, {0x50, 0x4B, 0x07, 0x08})) {
        return "ZIP";
    }
    if (starts_with(header, {0x4D, 0x5A})) {
        return "PE_EXE";
    }
    if (starts_with(header, {0x7F, 0x45, 0x4C, 0x46})) {
        return "ELF";
    }
    return "UNKNOWN";
}
