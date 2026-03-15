#include "json_writer.hpp"
#include "scanner.hpp"
#include "types.hpp"

#include <filesystem>
#include <iostream>
#include <optional>
#include <string>
#include <thread>

namespace {

void print_usage() {
    std::cout << "Usage:\n"
              << "  fileguard --path <dir> [--threads N] [--json report.json] [--max-size MB] [--follow-symlinks]\n";
}

std::optional<std::uintmax_t> parse_max_size_mb(const std::string& value) {
    try {
        std::uintmax_t mb = static_cast<std::uintmax_t>(std::stoull(value));
        return mb * 1024ULL * 1024ULL;
    } catch (...) {
        return std::nullopt;
    }
}

std::size_t default_thread_count() {
    const unsigned int hc = std::thread::hardware_concurrency();
    if (hc == 0) {
        return 4;
    }
    return static_cast<std::size_t>(hc);
}

}  // namespace

int main(int argc, char* argv[]) {
    if (argc < 3) {
        print_usage();
        return 1;
    }

    ScanOptions options;
    options.threads = default_thread_count();

    std::optional<std::filesystem::path> jsonOutputPath;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];

        if (arg == "--path") {
            if (i + 1 >= argc) {
                std::cerr << "Missing value for --path\n";
                return 1;
            }
            options.rootPath = argv[++i];
        } else if (arg == "--threads") {
            if (i + 1 >= argc) {
                std::cerr << "Missing value for --threads\n";
                return 1;
            }
            try {
                options.threads = static_cast<std::size_t>(std::stoull(argv[++i]));
                if (options.threads == 0) {
                    options.threads = 1;
                }
            } catch (...) {
                std::cerr << "Invalid value for --threads\n";
                return 1;
            }
        } else if (arg == "--json") {
            if (i + 1 >= argc) {
                std::cerr << "Missing value for --json\n";
                return 1;
            }
            jsonOutputPath = std::filesystem::path(argv[++i]);
        } else if (arg == "--max-size") {
            if (i + 1 >= argc) {
                std::cerr << "Missing value for --max-size\n";
                return 1;
            }
            auto parsed = parse_max_size_mb(argv[++i]);
            if (!parsed.has_value()) {
                std::cerr << "Invalid value for --max-size\n";
                return 1;
            }
            options.maxSizeBytes = parsed.value();
        } else if (arg == "--follow-symlinks") {
            options.followSymlinks = true;
        } else {
            std::cerr << "Unknown argument: " << arg << "\n";
            print_usage();
            return 1;
        }
    }

    if (options.rootPath.empty()) {
        std::cerr << "--path is required\n";
        print_usage();
        return 1;
    }

    std::error_code ec;
    if (!std::filesystem::exists(options.rootPath, ec) || !std::filesystem::is_directory(options.rootPath, ec)) {
        std::cerr << "Path is not a valid directory: " << options.rootPath << "\n";
        return 1;
    }

    ScanReport report = run_scan(options);

    std::cout << "FileGuard report\n";
    std::cout << "Root: " << report.root << "\n";
    std::cout << "Threads: " << report.threads << "\n";
    std::cout << "Duration: " << report.durationMs << " ms\n";
    std::cout << "Files scanned: " << report.stats.filesScanned << "\n";
    std::cout << "Files skipped: " << report.stats.filesSkipped << "\n";
    std::cout << "Bytes scanned: " << report.stats.bytesScanned << "\n\n";

    for (const auto& result : report.results) {
        std::cout << result.path << " | type=" << result.detectedType << " | size=" << result.size;
        if (!result.sha256.empty()) {
            std::cout << " | sha256=" << result.sha256;
        }
        std::cout << " | flags=";
        for (std::size_t i = 0; i < result.flags.size(); ++i) {
            std::cout << result.flags[i];
            if (i + 1 != result.flags.size()) {
                std::cout << ',';
            }
        }
        std::cout << "\n";
    }

    if (jsonOutputPath.has_value()) {
        if (!write_json_report(report, jsonOutputPath.value())) {
            std::cerr << "Failed to write JSON report: " << jsonOutputPath.value() << "\n";
            return 1;
        }
        std::cout << "\nJSON report written to: " << jsonOutputPath.value() << "\n";
    }

    return 0;
}
