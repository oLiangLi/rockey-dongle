#include "../base.h"

#ifndef _WIN32
#include <sys/time.h>
#else
#include <windows.h>
#endif /* _WIN32 */

rLANG_DECLARE_MACHINE

namespace {

#ifdef __EMSCRIPTEN__
rLANGWASMIMPORT(double, Platform_GetTickCount, (), {
  double result;
  EM_ASM_({ HEAPF64[$0>>>3] = Date.now(); }, &result);
  return result;
}, "rLANG", "jsGetTickCount")
#else /* __EMSCRIPTEN__ */
uint64_t Platform_GetTickCount() {
#ifdef _WIN32
  FILETIME ft;
  GetSystemTimeAsFileTime(&ft);
  return (((uint64_t)ft.dwHighDateTime << 32) | ft.dwLowDateTime) / 10000;
#else  /* _WIN32 */
  struct timeval now;
  gettimeofday(&now, nullptr);
  return now.tv_sec * 1000LL + now.tv_usec / 1000;
#endif /* _WIN32 */
}
#endif /* __EMSCRIPTEN__ */

uint64_t global_tick0_;

}  // namespace

rLANGEXPORT uint32_t rLANGAPI rLANG_GetVersion(void) {
  return rLANG_VERSION();
}

rLANGEXPORT uint64_t rLANGAPI rLANG_SetTickCount0(uint64_t tick) {
  if (0 == global_tick0_)
    global_tick0_ = Platform_GetTickCount();

  uint64_t result = global_tick0_;
  if (0 != tick)
    global_tick0_ = tick;
  return result;
}

rLANGEXPORT uint64_t rLANGAPI rLANG_GetTickCount(void) {
  if (0 == global_tick0_)
    global_tick0_ = Platform_GetTickCount();
  return Platform_GetTickCount() - global_tick0_;
}

rLANGEXPORT rlDate_t rLANGAPI rLANG_GetCurrentDate(void) {
#ifdef _WIN32
  FILETIME ft;
  GetSystemTimeAsFileTime(&ft);
  return (((int64_t)ft.dwHighDateTime << 32) | ft.dwLowDateTime) / 10 + (584754LL * 24 * 60 * 60) * 1000000;
#else
  struct timeval tv;
  gettimeofday(&tv, NULL);
  return (tv.tv_sec + (719528LL * 24 * 60 * 60)) * 1000000 + tv.tv_usec;
#endif
}

namespace {
static const int xdate_mdays[] = {0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334, 365};
static const int xdate_mday[] = {31 /**/, 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31, /**/ 31};

const int kDATE_NDAYS_Y400 = 400 * 365 + 97;
const int64_t kDATE_MICROSECONDS_ONEDAY = 24LL * 3600 * 1000000;
}  // namespace

rLANGEXPORT rlDate_t rLANGAPI rLANG_GetDateFromTime(const struct rlTM_t* tm) {
  int nday, y400, y = tm->tm_year, m = tm->tm_month - 1, d = tm->tm_mday;

  y += m / 12;
  m %= 12;
  if (m < 0) {
    --y, m += 12;
  }

  y400 = y / 400, y %= 400;
  if (y < 0) {
    --y400, y += 400;
  }

  nday = y400 * kDATE_NDAYS_Y400 + rLANG_LeapYearNdays(y) + xdate_mdays[m] + d - (m <= 1 && (rLANG_IsLeapYear(y)));
  return ((3600LL * 24) * nday + tm->tm_hour * 3600 + tm->tm_minute * 60 + tm->tm_second) * 1000000 +
         tm->tm_microsecond;
}

rLANGEXPORT void rLANGAPI rLANG_GetTimeFromDate(struct rlTM_t* tm, rlDate_t dt) {
  int y, m, d, diff, days, ny400, ns, nday = (int)(dt / kDATE_MICROSECONDS_ONEDAY);
  dt %= kDATE_MICROSECONDS_ONEDAY;

  if (dt < 0) {
    --nday, dt += kDATE_MICROSECONDS_ONEDAY;
  }

  tm->tm_wday = (nday + 0x3F707076) % 7;
  tm->tm_microsecond = dt % 1000000;
  ns = (int)(dt / 1000000);
  tm->tm_second = ns % 60;
  ns /= 60;
  tm->tm_minute = ns % 60;
  ns /= 60;
  tm->tm_hour = ns;

  ny400 = nday / kDATE_NDAYS_Y400;
  nday %= kDATE_NDAYS_Y400;

  if (nday < 0) {
    --ny400, nday += kDATE_NDAYS_Y400;
  }

  days = 100 * nday;
  y = days / 36524;
  days %= 36524;
  m = 1 + days / 3044;         /* [1..12] */
  d = 1 + (days % 3044) / 100; /* [1..31] */
  diff = rLANG_LeapYearNdays(y) + xdate_mdays[m - 1] + d - ((m <= 2 && rLANG_IsLeapYear(y))) - nday;

  if (diff > 0 && diff >= d) {
    if rLANG_UNLIKELY (m == 1) {
      --y;
      m = 12;
      d = 31 - (diff - d);
    } else {
      d = xdate_mday[m - 1] - (diff - d);
      if (--m == 2) {
        d += ((y & 3) == 0) && ((y % 100) != 0 || y % 400 == 0);
      }
    }
  } else {
    if rLANG_UNLIKELY ((d -= diff) > xdate_mday[m]) {
      if (m == 2) {
        if (((y & 3) == 0) && ((y % 100) != 0 || y % 400 == 0)) {
          if (d != 29) {
            m = 3, d -= 29;
          }
        } else {
          m = 3, d -= 28;
        }
      } else {
        d -= xdate_mday[m];
        if (m++ == 12) {
          ++y, m = 1;
        }
      }
    }
  }

  tm->tm_year = y + ny400 * 400;
  tm->tm_month = m;
  tm->tm_mday = d;
}

rLANG_DECLARE_END
