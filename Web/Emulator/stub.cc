
#include <base/base.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

rLANG_DECLARE_MACHINE

constexpr uint32_t TAG = rLANG_DECLARE_MAGIC_Xs("k@sys");

/**
 *! TODO: LiangLI, FileSystem ...
 */
rLANGEXPORT int __syscall_ioctl(int fd, int op, ...) {
  rlLOGE(TAG, "[NOT IMPL]%s", __FUNCTION__);
  return -ENOSYS;
}

rLANGEXPORT int __syscall_fcntl64(int fd, int cmd, ...) {
  rlLOGE(TAG, "[NOT IMPL]%s", __FUNCTION__);
  return -ENOSYS;
}

rLANGEXPORT int __syscall_fstat64(int fd, intptr_t buf) {
  if(fd == 10086) {
    auto* st = (struct stat*)buf;
    memset(st, 0, sizeof(*st));
    st->st_mode = S_IFCHR;
    return 0;
  }
  return -ENOSYS;
}

rLANGEXPORT int __syscall_stat64(intptr_t path, intptr_t buf) {
  rlLOGE(TAG, "[NOT IMPL]%s", __FUNCTION__);
  return -ENOSYS;
}

rLANGEXPORT int __syscall_dup(int fd) {
  rlLOGE(TAG, "[NOT IMPL]%s", __FUNCTION__);
  return -ENOSYS;
}

rLANGEXPORT int __syscall_mkdirat(int dirfd, intptr_t path, int mode) {
  rlLOGE(TAG, "[NOT IMPL]%s", __FUNCTION__);
  return -ENOSYS;
}

rLANGEXPORT int __syscall_newfstatat(int dirfd, intptr_t path, intptr_t buf, int flags) {
  rlLOGE(TAG, "[NOT IMPL]%s", __FUNCTION__);
  return -ENOSYS;
}

rLANGEXPORT int __syscall_lstat64(intptr_t path, intptr_t buf) {
  rlLOGE(TAG, "[NOT IMPL]%s", __FUNCTION__);
  return -ENOSYS;
}

rLANGEXPORT int __syscall_openat(int dirfd, intptr_t path, int flags, ...) {
  if (0 == strcmp((const char*)path, "/dev/random") || 0 == strcmp((const char*)path, "/dev/urandom")) {
    rlLOGI(TAG, "OpenAT: TRNG!");
    return 10086;
  }
  rlLOGE(TAG, "[NOT IMPL]__syscall_openat %s", (const char*)path);
  return -EPERM;
}

rLANGEXPORT int __syscall_getdents64(int fd, intptr_t dirp, size_t count) {
  return -ENOSYS;
}

/**
 *! MM
 */
rLANGWASMEXPORT void* MemoryManager(void* p, size_t sz) {
  if (!sz) {
    if (p)
      free(p);
    return nullptr;
  }

  if (!p)
    return malloc(sz);

  return realloc(p, sz);
}

rLANG_DECLARE_END

int main() {
  return 0;
}
