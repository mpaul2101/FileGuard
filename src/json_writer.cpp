#include "json_writer.hpp"

#include <fstream>
#include <string>

namespace {

std::string json_escape(const std::string& input) {
    std::string out;
    out.reserve(input.size() + 16);
    for (unsigned char c : input) {
        switch (c) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\b': out += "\\b"; break;
            case '\f': out += "\\f"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (c < 0x20) {
                    out += "\\u00";
                    static const char* hex = "0123456789abcdef";
                    out += hex[(c >> 4) & 0xF];
                    out += hex[c & 0xF];
                } else {
                    out += static_cast<char>(c);
                }
                break;
        }
    }
    return out;
}

void write_string(std::ofstream& out, const std::string& value) {
    out << '"' << json_escape(value) << '"';
}

}  // namespace

bool write_json_report(const ScanReport& report, const std::filesystem::path& outputPath) {
    std::ofstream out(outputPath, std::ios::binary);
    if (!out) {
        return false;
    }

    out << "{\n";
    out << "  \"root\": ";
    write_string(out, report.root);
    out << ",\n";

    out << "  \"threads\": " << report.threads << ",\n";
    out << "  \"duration_ms\": " << report.durationMs << ",\n";

    out << "  \"stats\": {\n";
    out << "    \"files_scanned\": " << report.stats.filesScanned << ",\n";
    out << "    \"files_skipped\": " << report.stats.filesSkipped << ",\n";
    out << "    \"bytes_scanned\": " << report.stats.bytesScanned << "\n";
    out << "  },\n";

    out << "  \"results\": [\n";
    for (std::size_t i = 0; i < report.results.size(); ++i) {
        const auto& item = report.results[i];
        out << "    {\n";

        out << "      \"path\": ";
        write_string(out, item.path);
        out << ",\n";

        out << "      \"size\": " << item.size << ",\n";

        out << "      \"extension\": ";
        write_string(out, item.extension);
        out << ",\n";

        out << "      \"detected_type\": ";
        write_string(out, item.detectedType);
        out << ",\n";

        out << "      \"sha256\": ";
        write_string(out, item.sha256);
        out << ",\n";

        out << "      \"flags\": [";
        for (std::size_t j = 0; j < item.flags.size(); ++j) {
            write_string(out, item.flags[j]);
            if (j + 1 != item.flags.size()) {
                out << ", ";
            }
        }
        out << "]\n";

        out << "    }";
        if (i + 1 != report.results.size()) {
            out << ",";
        }
        out << "\n";
    }
    out << "  ]\n";
    out << "}\n";

    return true;
}
