// Persisted profile selection. One line of text next to the credential store so
// the identity survives restarts without touching the encrypted store format.
#pragma once

#include "swpasskey/status.hpp"

#include <filesystem>
#include <string>
#include <string_view>

namespace swpk::compat {

// <data_dir>/compat-identity
std::filesystem::path selection_path(const std::filesystem::path& data_dir);

// Empty optional when the file is missing or names an unknown profile: the
// caller falls back to default_profile() rather than refusing to start.
std::string load_selected_id(const std::filesystem::path& path);

// 0600, O_NOFOLLOW, truncated in place. Creates the parent directory (0700).
Result<void> save_selected_id(const std::filesystem::path& path, std::string_view id);

}  // namespace swpk::compat
