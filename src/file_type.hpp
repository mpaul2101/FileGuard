#pragma once

#include <cstdint>
#include <string>
#include <vector>

std::string detect_file_type(const std::vector<std::uint8_t>& header);
