#include "sha256.hpp"

#include <openssl/evp.h>

#include <array>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <string>

bool compute_sha256_file(const std::filesystem::path& path, std::string& outHashHex, std::string& outError) {
    std::ifstream file(path, std::ios::binary);
    if (!file) {
        outError = "failed to open file";
        return false;
    }

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        outError = "failed to create digest context";
        return false;
    }

    bool ok = false;
    do {
        if (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) != 1) {
            outError = "failed to initialize SHA-256";
            break;
        }

        std::array<char, 64 * 1024> buffer{};
        while (file) {
            file.read(buffer.data(), static_cast<std::streamsize>(buffer.size()));
            std::streamsize readCount = file.gcount();
            if (readCount > 0) {
                if (EVP_DigestUpdate(ctx, buffer.data(), static_cast<std::size_t>(readCount)) != 1) {
                    outError = "failed to update SHA-256";
                    break;
                }
            }
        }

        if (!file.eof()) {
            outError = "failed during file read";
            break;
        }

        unsigned char digest[EVP_MAX_MD_SIZE]{};
        unsigned int digestLen = 0;
        if (EVP_DigestFinal_ex(ctx, digest, &digestLen) != 1) {
            outError = "failed to finalize SHA-256";
            break;
        }

        std::ostringstream oss;
        oss << std::hex << std::setfill('0');
        for (unsigned int i = 0; i < digestLen; ++i) {
            oss << std::setw(2) << static_cast<int>(digest[i]);
        }
        outHashHex = oss.str();
        ok = true;
    } while (false);

    EVP_MD_CTX_free(ctx);
    return ok;
}
