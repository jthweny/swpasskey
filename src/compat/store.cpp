#include "swpasskey/compat/store.hpp"

#include "swpasskey/compat/profile.hpp"
#include "swpasskey/log/log.hpp"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <fstream>

namespace swpk::compat {
namespace {

bool ensure_parent(const std::filesystem::path& file) {
  std::error_code ec;
  const auto dir = file.parent_path();
  if (dir.empty() || std::filesystem::is_directory(dir, ec)) {
    return true;
  }
  std::filesystem::create_directories(dir, ec);
  if (ec) {
    log::error("compat_mkdir_failed", {{"path", dir.string()}, {"err", ec.message()}});
    return false;
  }
  ::chmod(dir.c_str(), 0700);
  return true;
}

}  // namespace

std::filesystem::path selection_path(const std::filesystem::path& data_dir) {
  return data_dir / "compat-identity";
}

std::string load_selected_id(const std::filesystem::path& path) {
  std::ifstream in(path);
  if (!in) {
    return {};
  }
  std::string id;
  std::getline(in, id);
  while (!id.empty() && (id.back() == '\r' || id.back() == ' ' || id.back() == '\t')) {
    id.pop_back();
  }
  if (id.empty()) {
    return {};
  }
  if (find_profile(id) == nullptr) {
    log::warn("compat_identity_unknown", {{"id", id}, {"action", "using the stock profile"}});
    return {};
  }
  return id;
}

Result<void> save_selected_id(const std::filesystem::path& path, std::string_view id) {
  if (find_profile(id) == nullptr) {
    return std::unexpected(Status::InvalidParameter);
  }
  if (!ensure_parent(path)) {
    return std::unexpected(Status::Other);
  }
  const int fd = ::open(path.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC, 0600);
  if (fd < 0) {
    log::error("compat_identity_write_failed",
               {{"path", path.string()}, {"errno", std::strerror(errno)}});
    return std::unexpected(Status::Other);
  }
  const std::string line = std::string(id) + "\n";
  const ssize_t n = ::write(fd, line.data(), line.size());
  ::fsync(fd);
  ::close(fd);
  return n == static_cast<ssize_t>(line.size()) ? Result<void>{}
                                                : Result<void>(std::unexpected(Status::Other));
}

}  // namespace swpk::compat
