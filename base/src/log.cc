#include "../base.h"

#ifdef _WIN32
#include <windows.h>
#else /* _WIN32 */
#include <sys/types.h>
#include <unistd.h>
#endif /* _WIN32 */

#ifdef __CYGWIN__
#include <windows.h>
namespace {
int gettid() {
  return static_cast<int>(GetCurrentThreadId());
}
}  // namespace
#endif /* __CYGWIN__ */

rLANG_DECLARE_MACHINE

namespace {

rlLogLevel global_log_level = rlLOG_INFO;

#ifndef rLANG_CONFIG_LOGDATA_SIZEMAX
#define rLANG_CONFIG_LOGDATA_SIZEMAX 1024
#endif /* rLANG_CONFIG_LOGDATA_SIZEMAX */

static int rLANGAPI rlLog_vsnprintf(char* buff, int size, const char* fmt, va_list ap) {
  int result = vsnprintf(buff, size, fmt, ap);
  if (result >= size)
    result = size - 1;
  return result;
}

#if defined(_WIN32)
static void rLANGAPI logWrite0(HANDLE hCCON, const char* info) {
  if (NULL != hCCON) {
    fputs(info, stderr);
  }
  OutputDebugStringA(info);
}

static void rLANGAPI logWrite(HANDLE hCCON, const uint8_t* data, int len) {
  int k, i;
  char line[72], *p, c1, c2;

  for (; len > 0; len -= 16, data += 16) {
    k = len;
    p = line;
    if (k > 16) {
      k = 16;
    }

    for (i = 0; i < k; ++i) {
      c1 = data[i] >> 4;
      c2 = data[i] & 0x0F;
      c1 = c1 < 10 ? '0' + c1 : 'A' - 10 + c1;
      c2 = c2 < 10 ? '0' + c2 : 'A' - 10 + c2;
      *p++ = c1;
      *p++ = c2;
      *p++ = ' ';
    }
    for (; i < 18; ++i, p += 3) {
      p[0] = p[1] = p[2] = ' ';
    }
    for (i = 0; i < k; ++i) {
      if (data[i] >= 0x20 && data[i] < 0x7F) {
        *p++ = (char)data[i];
      } else {
        *p++ = '.';
      }
    }
    *p++ = '\n';
    *p++ = 0;

    logWrite0(hCCON, line);
  }
}

void platformLoggingWrite(int level, uint32_t tag, int line, const void* data, int len, const char* fmt, va_list ap) {
  char sTAG[8];
  if (level <= rlLOG_NONE || global_log_level < level || !tag)
    return;

  char info[rLANG_CONFIG_LOGDATA_SIZEMAX + 256], *p = info;
  HANDLE hCCON = GetStdHandle(STD_ERROR_HANDLE);
  if (INVALID_HANDLE_VALUE == hCCON)
    hCCON = nullptr;

  if (!hCCON && !IsDebuggerPresent())
    return;

  if (hCCON) {
    static const WORD con_attr[] = {FOREGROUND_INTENSITY | FOREGROUND_RED,
                                    FOREGROUND_INTENSITY | FOREGROUND_RED,
                                    FOREGROUND_INTENSITY | FOREGROUND_RED | FOREGROUND_GREEN,
                                    FOREGROUND_INTENSITY | FOREGROUND_GREEN,
                                    FOREGROUND_INTENSITY | FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE,
                                    FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE};
    SetConsoleTextAttribute(hCCON, con_attr[level]);
  }

  int pid = static_cast<int>(GetCurrentProcessId()), tid = static_cast<int>(GetCurrentThreadId());

  rLANG_DECLARE_MAGIC_Vs(tag, sTAG);
  if (data && len > 0) {
    p += sprintf(info, "%c (%lld,%d,%d) %s:%d %p:%d ", "*EWIDV"[level], (long long)rLANG_GetTickCount(), pid, tid, sTAG,
                 line, data, len);
    p += rlLog_vsnprintf(p, rLANG_CONFIG_LOGDATA_SIZEMAX, fmt, ap);
    if (p[-1] != '\n')
      *p++ = '\n';
    *p++ = 0;

    logWrite0(hCCON, info);
    if (len > rLANG_CONFIG_LOGDATA_SIZEMAX)
      len = rLANG_CONFIG_LOGDATA_SIZEMAX;
    logWrite(hCCON, (const uint8_t*)data, len);
  } else {
    p +=
        sprintf(info, "%c (%lld,%d,%d) %s:%d ", "*EWIDV"[level], (long long)rLANG_GetTickCount(), pid, tid, sTAG, line);
    p += rlLog_vsnprintf(p, rLANG_CONFIG_LOGDATA_SIZEMAX, fmt, ap);
    if (p[-1] != '\n')
      *p++ = '\n';
    *p++ = 0;
    logWrite0(hCCON, info);
  }

  if (NULL != hCCON)
    SetConsoleTextAttribute(hCCON, 0x0F);
}
#endif /* _WIN32 */

#if defined(__linux__) || defined(__CYGWIN__) || defined(X_BUILD_native)

#ifdef X_BUILD_native
static int gettid() {
  return -1;
}
#endif /* X_BUILD_native */

static void rLANGAPI logWrite(const char* afmt, const char* efmt, const uint8_t* data, int len) {
  if (!afmt)
    afmt = "";
  if (!efmt)
    efmt = "";

  int k, i;
  char line[72], *p, c1, c2;

  for (; len > 0; len -= 16, data += 16) {
    k = len;
    p = line;
    if (k > 16) {
      k = 16;
    }

    for (i = 0; i < k; ++i) {
      c1 = data[i] >> 4;
      c2 = data[i] & 0x0F;
      c1 = c1 < 10 ? '0' + c1 : 'A' - 10 + c1;
      c2 = c2 < 10 ? '0' + c2 : 'A' - 10 + c2;
      *p++ = c1;
      *p++ = c2;
      *p++ = ' ';
    }
    for (; i < 18; ++i, p += 3) {
      p[0] = p[1] = p[2] = ' ';
    }
    for (i = 0; i < k; ++i) {
      if (data[i] >= 0x20 && data[i] < 0x7F) {
        *p++ = (char)data[i];
      } else {
        *p++ = '.';
      }
    }
    *p++ = 0;

    fprintf(stderr, "%s%s%s\n", afmt, line, efmt);
  }
}

void platformLoggingWrite(int level, uint32_t tag, int line, const void* data, int len, const char* fmt, va_list ap) {
  char sTAG[8];
  if (level <= rlLOG_NONE || global_log_level < level || !tag)
    return;

  const char *afmt, *efmt;
  switch (level) {
    default:
      afmt = efmt = nullptr;
      break;
    case rlLOG_INFO:
      afmt = "\033[0;32m";
      efmt = "\033[0m";
      break;
    case rlLOG_WARN:
      afmt = "\033[0;33m";
      efmt = "\033[0m";
      break;
    case rlLOG_ERROR:
      afmt = "\033[0;31m";
      efmt = "\033[0m";
      break;
  }

  char info[rLANG_CONFIG_LOGDATA_SIZEMAX + 256], *p = info;
  rLANG_DECLARE_MAGIC_Vs(tag, sTAG);

  pid_t pid = getpid(), tid = gettid();

  if (data && len > 0) {
    if (afmt)
      p += sprintf(p, "%s", afmt);
    p += sprintf(p, "%c (%lld,%d,%d) %s:%d %p:%d ", "*EWIDV"[level], (long long)rLANG_GetTickCount(), pid, tid, sTAG,
                 line, data, len);
    p += rlLog_vsnprintf(p, rLANG_CONFIG_LOGDATA_SIZEMAX, fmt, ap);
    if (p[-1] == '\n')
      --p;
    if (efmt)
      sprintf(p, "%s", efmt);
    *p++ = '\n';
    *p++ = 0;
    fprintf(stderr, "%s", info);

    if (len > rLANG_CONFIG_LOGDATA_SIZEMAX)
      len = rLANG_CONFIG_LOGDATA_SIZEMAX;

    logWrite(afmt, efmt, static_cast<const uint8_t*>(data), len);
  } else {
    if (afmt)
      p += sprintf(p, "%s", afmt);
    p += sprintf(p, "%c (%lld,%d,%d) %s:%d ", "*EWIDV"[level], (long long)rLANG_GetTickCount(), pid, tid, sTAG, line);
    p += rlLog_vsnprintf(p, rLANG_CONFIG_LOGDATA_SIZEMAX, fmt, ap);
    if (p[-1] == '\n')
      --p;
    if (efmt)
      p += sprintf(p, "%s", efmt);
    *p++ = '\n';
    *p++ = 0;

    fprintf(stderr, "%s", info);
  }
}

#endif /* Linux || Cygwin */

#ifdef __EMSCRIPTEN__

rLANGWASMIMPORT(
    void,
    jsLogWrite,
    (int level, char* message, int size),
    {
      EM_ASM_(
          {
            const level = $0;
            const message = UTF8ToString($1, $2);
            switch (level) {
              case 1:
                console.error(`% c$ { message }`, "color: red");
                break;
              case 2:
                console.warn(`% c$ { message }`, "color: darkorange");
                break;
              case 3:
                console.info(`% c$ { message }`, "color: blue");
                break;
              default:
                console.log(`% c$ { message }`, "color: dimgray");
                break;
            }
          },
          level, message, size);
    },
    "rLANG",
    "jsLogWrite")

static void rLANGAPI logWrite(int level, const uint8_t* data, int len) {
  int k, i;
  char line[72], *p, c1, c2;

  for (; len > 0; len -= 16, data += 16) {
    k = len;
    p = line;
    if (k > 16) {
      k = 16;
    }

    for (i = 0; i < k; ++i) {
      c1 = data[i] >> 4;
      c2 = data[i] & 0x0F;
      c1 = c1 < 10 ? '0' + c1 : 'A' - 10 + c1;
      c2 = c2 < 10 ? '0' + c2 : 'A' - 10 + c2;
      *p++ = c1;
      *p++ = c2;
      *p++ = ' ';
    }
    for (; i < 18; ++i, p += 3) {
      p[0] = p[1] = p[2] = ' ';
    }
    for (i = 0; i < k; ++i) {
      if (data[i] >= 0x20 && data[i] < 0x7F) {
        *p++ = (char)data[i];
      } else {
        *p++ = '.';
      }
    }
    *p = 0;

    jsLogWrite(level, line, static_cast<int>(p - line));
  }
}

void platformLoggingWrite(int level, uint32_t tag, int line, const void* data, int len, const char* fmt, va_list ap) {
  char sTAG[8];
  if (level <= rlLOG_NONE || global_log_level < level || !tag)
    return;

  char info[rLANG_CONFIG_LOGDATA_SIZEMAX + 256], *p = info;
  rLANG_DECLARE_MAGIC_Vs(tag, sTAG);

  if (data && len > 0) {
    p += sprintf(p, "%c (%lld) %s %p:%d ", "*EWIDV"[level], (long long)rLANG_GetTickCount(), sTAG, data, len);
    p += rlLog_vsnprintf(p, rLANG_CONFIG_LOGDATA_SIZEMAX, fmt, ap);
    if (p[-1] != '\n')
      *p++ = '\n';
    *p = 0;
    jsLogWrite(level, info, p - info);

    if (len > rLANG_CONFIG_LOGDATA_SIZEMAX)
      len = rLANG_CONFIG_LOGDATA_SIZEMAX;

    logWrite(level, static_cast<const uint8_t*>(data), len);
  } else {
    p += sprintf(p, "%c (%lld) %s ", "*EWIDV"[level], (long long)rLANG_GetTickCount(), sTAG);
    p += rlLog_vsnprintf(p, rLANG_CONFIG_LOGDATA_SIZEMAX, fmt, ap);
    if (p[-1] != '\n')
      *p++ = '\n';
    *p = 0;

    jsLogWrite(level, info, p - info);
  }
}

#endif /* __EMSCRIPTEN__ */

}  // namespace

rLANGEXPORT rlLogLevel rLANGAPI rlLoggingSetLevel(rlLogLevel level) {
  rlLogLevel origin = global_log_level;

  if (level >= rlLOG_VERBOSE) {
    global_log_level = rlLOG_VERBOSE;
  } else if (level >= rlLOG_ERROR) {
    global_log_level = level;
  }

  return origin;
}

rLANGEXPORT void rlLoggingWriteEx(int level, uint32_t tag, int line, const void* data, int len, const char* fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  platformLoggingWrite(level, tag, line, data, len, fmt, ap);
  va_end(ap);
}

rLANGEXPORT void rlLoggingWrite(int level, uint32_t tag, int line, const char* fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  platformLoggingWrite(level, tag, line, nullptr, 0, fmt, ap);
  va_end(ap);
}

rLANG_DECLARE_END
