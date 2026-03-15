#pragma once

#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

struct ScanOptions {
    std::filesystem::path rootPath;
    std::size_t threads = 0;
    std::optional<std::uintmax_t> maxSizeBytes;
    bool followSymlinks = false;
};

struct ScanStats {
    std::uint64_t filesScanned = 0;
    std::uint64_t filesSkipped = 0;
    std::uint64_t bytesScanned = 0;
};

struct FileResult {
    std::string path;
    std::uintmax_t size = 0;
    std::string extension;
    std::string detectedType;
    std::string sha256;
    std::vector<std::string> flags;
};

struct ScanReport {
    std::string root;
    std::size_t threads = 0;
    std::uint64_t durationMs = 0;
    ScanStats stats;
    std::vector<FileResult> results;
};
