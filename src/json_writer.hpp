#pragma once

#include "types.hpp"

#include <filesystem>

bool write_json_report(const ScanReport& report, const std::filesystem::path& outputPath);
