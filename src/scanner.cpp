#include "scanner.hpp"

#include "file_type.hpp"
#include "sha256.hpp"
#include "thread_pool.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cctype>
#include <fstream>
#include <filesystem>
#include <mutex>
#include <optional>
#include <set>
#include <string>
#include <system_error>
#include <vector>

namespace {

std::string to_lower(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return value;
}

std::string type_to_expected_extension(const std::string& type) {
    if (type == "PDF") return ".pdf";
    if (type == "PNG") return ".png";
    if (type == "JPEG") return ".jpg";
    if (type == "ZIP") return ".zip";
    if (type == "PE_EXE") return ".exe";
    if (type == "ELF") return ".elf";
    return "";
}

bool has_allowed_jpeg_extension(const std::string& extensionLower) {
    return extensionLower == ".jpg" || extensionLower == ".jpeg";
}

bool has_double_extension_suspicion(const std::filesystem::path& filePath) {
    static const std::set<std::string> suspiciousTailExt = {
        "exe", "scr", "bat", "cmd", "com", "ps1", "js", "vbs", "jar"
    };
    static const std::set<std::string> lureExt = {
        "pdf", "png", "jpg", "jpeg", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "zip"
    };

    std::string filename = to_lower(filePath.filename().string());
    std::vector<std::string> parts;
    std::size_t start = 0;
    while (start < filename.size()) {
        auto dotPos = filename.find('.', start);
        if (dotPos == std::string::npos) {
            parts.push_back(filename.substr(start));
            break;
        }
        parts.push_back(filename.substr(start, dotPos - start));
        start = dotPos + 1;
    }

    if (parts.size() < 3) {
        return false;
    }

    const std::string& secondLast = parts[parts.size() - 2];
    const std::string& last = parts.back();
    return lureExt.count(secondLast) > 0 && suspiciousTailExt.count(last) > 0;
}

std::string display_path(const std::filesystem::path& path, const std::filesystem::path& root) {
    std::error_code ec;
    auto rel = std::filesystem::relative(path, root, ec);
    if (!ec) {
        return rel.generic_string();
    }
    return path.generic_string();
}

FileResult process_file(const std::filesystem::path& path, std::uintmax_t size, const std::filesystem::path& root) {
    FileResult result;
    result.path = display_path(path, root);
    result.size = size;
    result.extension = to_lower(path.extension().string());

    std::ifstream stream(path, std::ios::binary);
    if (!stream) {
        result.detectedType = "UNKNOWN";
        result.flags.push_back("read error");
        return result;
    }

    std::vector<std::uint8_t> header(16, 0);
    stream.read(reinterpret_cast<char*>(header.data()), static_cast<std::streamsize>(header.size()));
    std::streamsize readCount = stream.gcount();
    if (readCount < 0) {
        result.detectedType = "UNKNOWN";
        result.flags.push_back("read error");
        return result;
    }
    header.resize(static_cast<std::size_t>(readCount));

    result.detectedType = detect_file_type(header);

    std::string hash;
    std::string error;
    if (!compute_sha256_file(path, hash, error)) {
        result.flags.push_back("read error");
    } else {
        result.sha256 = hash;
    }

    if (result.detectedType == "PE_EXE" || result.detectedType == "ELF") {
        result.flags.push_back("is executable");
    }

    if (has_double_extension_suspicion(path)) {
        result.flags.push_back("suspicious double extension");
    }

    if (result.detectedType != "UNKNOWN") {
        if (result.detectedType == "JPEG") {
            if (!has_allowed_jpeg_extension(result.extension)) {
                result.flags.push_back("extension mismatch");
            }
        } else {
            std::string expected = type_to_expected_extension(result.detectedType);
            if (!expected.empty() && result.extension != expected) {
                result.flags.push_back("extension mismatch");
            }
        }
    }

    if (result.flags.empty()) {
        result.flags.push_back("ok");
    }

    return result;
}

}  // namespace

ScanReport run_scan(const ScanOptions& options) {
    const auto startedAt = std::chrono::steady_clock::now();

    ScanReport report;
    report.root = options.rootPath.generic_string();
    report.threads = options.threads;

    std::mutex resultMutex;
    std::atomic<std::uint64_t> filesScanned{0};
    std::atomic<std::uint64_t> filesSkipped{0};
    std::atomic<std::uint64_t> bytesScanned{0};

    ThreadPool pool(options.threads);

    std::filesystem::directory_options iterOptions = std::filesystem::directory_options::skip_permission_denied;
    if (options.followSymlinks) {
        iterOptions |= std::filesystem::directory_options::follow_directory_symlink;
    }

    std::error_code ec;
    std::filesystem::recursive_directory_iterator it(options.rootPath, iterOptions, ec);
    std::filesystem::recursive_directory_iterator end;

    if (ec) {
        pool.shutdown();
        report.durationMs = static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - startedAt).count());
        return report;
    }

    for (; it != end; it.increment(ec)) {
        if (ec) {
            ec.clear();
            continue;
        }

        const auto& entry = *it;
        std::error_code entryEc;

        if (!options.followSymlinks && entry.is_symlink(entryEc) && !entryEc) {
            continue;
        }

        if (!entry.is_regular_file(entryEc) || entryEc) {
            continue;
        }

        std::uintmax_t fileSize = entry.file_size(entryEc);
        if (entryEc) {
            continue;
        }

        if (options.maxSizeBytes.has_value() && fileSize > options.maxSizeBytes.value()) {
            FileResult skipped;
            skipped.path = display_path(entry.path(), options.rootPath);
            skipped.size = fileSize;
            skipped.extension = to_lower(entry.path().extension().string());
            skipped.detectedType = "UNKNOWN";
            skipped.flags = {"skipped size"};
            {
                std::lock_guard<std::mutex> lock(resultMutex);
                report.results.push_back(std::move(skipped));
            }
            filesSkipped.fetch_add(1, std::memory_order_relaxed);
            continue;
        }

        const auto filePath = entry.path();
        pool.enqueue([&, filePath, fileSize]() {
            FileResult result = process_file(filePath, fileSize, options.rootPath);
            {
                std::lock_guard<std::mutex> lock(resultMutex);
                report.results.push_back(std::move(result));
            }
            filesScanned.fetch_add(1, std::memory_order_relaxed);
            bytesScanned.fetch_add(static_cast<std::uint64_t>(fileSize), std::memory_order_relaxed);
        });
    }

    pool.shutdown();

    report.stats.filesScanned = filesScanned.load(std::memory_order_relaxed);
    report.stats.filesSkipped = filesSkipped.load(std::memory_order_relaxed);
    report.stats.bytesScanned = bytesScanned.load(std::memory_order_relaxed);

    std::sort(report.results.begin(), report.results.end(), [](const FileResult& a, const FileResult& b) {
        return a.path < b.path;
    });

    report.durationMs = static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - startedAt).count());

    return report;
}
