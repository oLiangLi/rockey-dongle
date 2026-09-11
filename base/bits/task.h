#pragma once

#ifndef __WTINC_BASE_TASK_H__
#define __WTINC_BASE_TASK_H__

#ifndef ___WTINC_BITS_BASE_H__
#include "./base.h"
#endif /* ___WTINC_BITS_BASE_H__ */

rLANG_DECLARE_MACHINE

/**
 *! 并入自上游(定时任务组): 以 RB-Tree 按 next_ticks_ 排队, 在 ExecuteTask 中回调到期的任务。
 *! 时钟源与延时由 rlTaskGroupDefault 按平台装配(宿主用 std::chrono, 设备用 rLANG_GetTickCount)。
 */
struct rlTaskGroup_t;
struct rlTaskNode_t {
  rLANG_RBTREE_DECLARE_NODE_ENTRY(1);
  void(rLANGAPI* Closure)(struct rlTaskGroup_t* group, struct rlTaskNode_t* self, int64_t ticks);
  int64_t next_ticks_;
};

struct rlTaskGroup_t {
  void* tasks_;        /* RB-Tree, rlTaskNode_t ... */
  int64_t last_ticks_; /* private: last ExecuteTask ticks ... */

  /**
   *!
   */
  int64_t(rLANGAPI* GetTicks)(struct rlTaskGroup_t* group);

  /**
   *! **注意**: 通过BusyLoop延时, 通常不应该用于毫秒以上的延时, 请使用ScheduleTask在指定的时刻回调 ...
   */
  int(rLANGAPI* DelayUs)(struct rlTaskGroup_t* group, int us);

  /**
   *!
   */
  int(rLANGAPI* TicksFromUs)(struct rlTaskGroup_t* group, int us);
  int(rLANGAPI* UsFromTicks)(struct rlTaskGroup_t* group, int ticks);

  /**
   *!
   */
  int(rLANGAPI* ScheduleTask)(struct rlTaskGroup_t* group, struct rlTaskNode_t* task, int64_t ticks);
  int(rLANGAPI* UnscheduleTask)(struct rlTaskGroup_t* group, struct rlTaskNode_t* task);
  int(rLANGAPI* ExecuteTask)(struct rlTaskGroup_t* group, int64_t ticks);

  /**
   *!
   */
  int64_t(rLANGAPI* NextTicks)(struct rlTaskGroup_t* group);
};

/**
 *! ticks 不小于最后一次调度指定的时间戳 ...
 */
rLANGEXPORT int rLANGAPI rlTaskGroup_DefaultScheduleTask(struct rlTaskGroup_t* group,
                                                         struct rlTaskNode_t* task,
                                                         int64_t ticks);
rLANGEXPORT int rLANGAPI rlTaskGroup_DefaultUnscheduleTask(struct rlTaskGroup_t* group,
                                                           struct rlTaskNode_t* task);
rLANGEXPORT int64_t rLANGAPI rlTaskGroup_DefaultNextTicks(struct rlTaskGroup_t* group);
rLANGEXPORT void rLANGAPI rlTaskGroupDefault(struct rlTaskGroup_t* group);

/**
 *! 在单次调用中, 系统时间戳冻结于 ticks ...
 */
rLANGEXPORT int rLANGAPI rlTaskGroup_DefaultExecuteTask(struct rlTaskGroup_t* group, int64_t ticks);

/**
 *!
 */
rlBASE_INLINE void rLANGAPI rlTaskNode_SetPrivateContext(struct rlTaskNode_t* task, void* self) {
  uintptr_t v = (uintptr_t)self;
  rLANG_VERIFY_EQ(0, v & 1); /* align(2), last bit for color ... */
  rLANG_RBTREE_USER_DATA(task) = v;
}
rlBASE_INLINE void* rLANGAPI rlTaskNode_GetPrivateContext(struct rlTaskNode_t* task) {
  return (void*)(~(uintptr_t)1 & rLANG_RBTREE_USER_DATA(task));
}

/**
 *!
 */
rlBASE_INLINE int64_t rLANGAPI rlTaskGroup_GetLastTicks(struct rlTaskGroup_t* group) {
  return group->last_ticks_;
}
rlBASE_INLINE int64_t rLANGAPI rlTaskGroup_GetTicks(struct rlTaskGroup_t* group) {
  return (*group->GetTicks)(group);
}
rlBASE_INLINE int rLANGAPI rlTaskGroup_DelayUs(struct rlTaskGroup_t* group, int us) {
  return (*group->DelayUs)(group, us);
}

rlBASE_INLINE int rLANGAPI rlTaskGroup_TicksFromUs(struct rlTaskGroup_t* group, int us) {
  return (*group->TicksFromUs)(group, us);
}
rlBASE_INLINE int rLANGAPI rlTaskGroup_UsFromTicks(struct rlTaskGroup_t* group, int ticks) {
  return (*group->UsFromTicks)(group, ticks);
}
rlBASE_INLINE int rLANGAPI rlTaskGroup_ScheduleTask(struct rlTaskGroup_t* group,
                                                    struct rlTaskNode_t* task,
                                                    int64_t ticks) {
  return (*group->ScheduleTask)(group, task, ticks);
}
rlBASE_INLINE int rLANGAPI rlTaskGroup_ScheduleTaskNext(struct rlTaskGroup_t* group,
                                                        struct rlTaskNode_t* task,
                                                        int64_t ticks) {
  ticks += rlTaskGroup_GetTicks(group);
  return (*group->ScheduleTask)(group, task, ticks);
}
rlBASE_INLINE int rLANGAPI rlTaskGroup_UnscheduleTask(struct rlTaskGroup_t* group,
                                                      struct rlTaskNode_t* task) {
  return (*group->UnscheduleTask)(group, task);
}
rlBASE_INLINE int rLANGAPI rlTaskGroup_ExecuteTask(struct rlTaskGroup_t* group, int64_t ticks) {
  return (*group->ExecuteTask)(group, ticks);
}
rlBASE_INLINE int64_t rLANGAPI rlTaskGroup_NextTicks(struct rlTaskGroup_t* group) {
  return (*group->NextTicks)(group);
}

rLANG_DECLARE_END

#endif /* __WTINC_BASE_TASK_H__ */
