#pragma once

#include <filesystem>
#include <string>

bool compute_sha256_file(const std::filesystem::path& path, std::string& outHashHex, std::string& outError);
