#include <windows.h>
#include <cstddef>
#include <cstdint>

namespace {
constexpr unsigned RelativeJumpSize = 5;
constexpr unsigned ShortJumpSize = 2;
constexpr unsigned IndirectBranchSize = 6;
constexpr unsigned MemorySlotSize = 64;

enum Status : uint32_t {
    Success, CaptureFailed, UnmappedInstruction, ApplyFailed, SuspendFailed,
    ResumeFailed, PatchChanged, ProtectionChangeFailed, ProtectionRestoreFailed, CacheFlushFailed, InvalidInput
};

struct HookPlan {
    void* target;
    void* trampoline;
    void* relay;
    void* destination;
    uint64_t absoluteCalls;
    uint64_t absoluteConditionalJumps;
    uint32_t boundaryCount;
    uint32_t patchAbove;
    uint32_t enabled;
    uint8_t oldIps[64];
    uint8_t newIps[64];
    uint8_t backup[8];
};

struct alignas(16) ThreadEntry {
    HANDLE thread;
#ifndef _WIN64
    uint32_t handlePadding;
#endif
    uint64_t originalIp;
    uint64_t plannedIp;
    uint32_t suspended;
    uint32_t exited;
    alignas(16) CONTEXT context;
#ifndef _WIN64
    uint32_t tailPadding;
#endif
};

struct Result {
    Status status;
    DWORD error;
    DWORD rollbackError;
    DWORD resumeError;
    uint64_t failedIp;
    uint32_t patchWritten;
};

static_assert(offsetof(ThreadEntry, context) == 32);
static_assert(sizeof(Result) == 32);
#ifdef _WIN64
static_assert(sizeof(HookPlan) == 200);
static_assert(sizeof(ThreadEntry) == 1264);
#else
static_assert(sizeof(HookPlan) == 184);
static_assert(sizeof(ThreadEntry) == 752);
#endif

uint64_t Address(const void* p) noexcept { return reinterpret_cast<uintptr_t>(p); }

uint64_t ReadIp(const CONTEXT& context) noexcept {
#ifdef _WIN64
    return context.Rip;
#else
    return context.Eip;
#endif
}

void WriteIp(CONTEXT& context, uint64_t ip) noexcept {
#ifdef _WIN64
    context.Rip = ip;
#else
    context.Eip = static_cast<DWORD>(ip);
#endif
}

// MinHook FindOldIP/FindNewIP, plus known continuations of expanded x64 CALL/Jcc.
bool MapIp(const HookPlan& hook, uint64_t ip, bool enable, uint64_t& mapped) noexcept {
    const auto target = Address(hook.target);
    const auto trampoline = Address(hook.trampoline);
    mapped = ip;
    if (!enable) {
        if (ip == target) return true;
        if (hook.patchAbove && ip == target - RelativeJumpSize) { mapped = target; return true; }
        if (hook.relay && ip == Address(hook.relay)) { mapped = target; return true; }
    }
    for (uint32_t i = 0; i < hook.boundaryCount; ++i) {
        const auto oldIp = target + hook.oldIps[i];
        const auto newIp = trampoline + hook.newIps[i];
        if (!enable && !hook.enabled && ip == oldIp) return true;
        if (ip == (enable ? oldIp : newIp)) { mapped = enable ? newIp : oldIp; return true; }
        if (!enable && (hook.absoluteCalls & (uint64_t{1} << i)) && ip == newIp + IndirectBranchSize) {
            if (i + 1 == hook.boundaryCount) return false;
            mapped = target + hook.oldIps[i + 1];
            return true;
        }
        if (!enable && (hook.absoluteConditionalJumps & (uint64_t{1} << i)) && ip == newIp + ShortJumpSize) {
            const auto address = static_cast<const uint8_t*>(hook.trampoline) + hook.newIps[i] + ShortJumpSize + IndirectBranchSize;
            mapped = 0;
            for (unsigned b = 0; b < sizeof(mapped); ++b) mapped |= uint64_t{address[b]} << (b * 8);
            return true;
        }
    }
    const auto patchStart = hook.patchAbove ? target - RelativeJumpSize : target;
    const auto patchEnd = target + (hook.patchAbove ? ShortJumpSize : RelativeJumpSize);
    // Do not round an unknown IP to a nearby instruction. New trampoline sequences need explicit mappings.
    if (ip >= patchStart && ip < patchEnd) return false;
    return enable || ip < trampoline || ip >= trampoline + MemorySlotSize;
}

void Capture(ThreadEntry* threads, uint32_t count, const HookPlan* hooks, uint32_t hookCount,
    bool enable, Result& result) noexcept {
    for (uint32_t i = 0; i < count; ++i) {
        auto& entry = threads[i];
        if (entry.exited) continue;
        entry.context.ContextFlags = CONTEXT_CONTROL;
        if (!GetThreadContext(entry.thread, &entry.context)) {
            const auto error = GetLastError();
            if (WaitForSingleObject(entry.thread, 0) == WAIT_OBJECT_0) { entry.exited = 1; continue; }
            result.status = CaptureFailed; result.error = error; return;
        }
        entry.originalIp = entry.plannedIp = ReadIp(entry.context);
        for (uint32_t h = hookCount; h != 0; --h) {
            const auto ip = entry.plannedIp;
            if (!MapIp(hooks[h - 1], ip, enable, entry.plannedIp)) {
                result.status = UnmappedInstruction; result.failedIp = ip; return;
            }
        }
    }
}

DWORD Rollback(ThreadEntry* threads, uint32_t applied) noexcept {
    DWORD error = 0;
    while (applied != 0) {
        auto& entry = threads[--applied];
        if (entry.exited || entry.originalIp == entry.plannedIp) continue;
        WriteIp(entry.context, entry.originalIp);
        if (!SetThreadContext(entry.thread, &entry.context) && error == 0) error = GetLastError();
    }
    return error;
}

void Apply(ThreadEntry* threads, uint32_t count, uint32_t& applied, Result& result) noexcept {
    applied = 0;
    for (uint32_t i = 0; i < count; ++i) {
        auto& entry = threads[i];
        if (entry.exited || entry.originalIp == entry.plannedIp) continue;
        WriteIp(entry.context, entry.plannedIp);
        applied = i + 1;
        if (!SetThreadContext(entry.thread, &entry.context)) {
            result.status = ApplyFailed; result.error = GetLastError();
            result.rollbackError = Rollback(threads, applied);
            applied = 0;
            return;
        }
    }
}

void Patch(const HookPlan& hook, bool enable, Result& result) noexcept {
    auto target = static_cast<uint8_t*>(hook.target);
    auto patch = target - (hook.patchAbove ? RelativeJumpSize : 0);
    const auto size = RelativeJumpSize + (hook.patchAbove ? ShortJumpSize : 0);
    uint8_t expected[RelativeJumpSize + ShortJumpSize] = { 0xE9 };
    const auto displacement = static_cast<uint32_t>(Address(hook.destination) - Address(patch + RelativeJumpSize));
    for (unsigned i = 0; i < sizeof(displacement); ++i) expected[i + 1] = static_cast<uint8_t>(displacement >> (i * 8));
    expected[RelativeJumpSize] = 0xEB;
    expected[RelativeJumpSize + 1] = static_cast<uint8_t>(-static_cast<int>(RelativeJumpSize + ShortJumpSize));
    // Another hook may own these bytes. Remove newer hooks first; do not overwrite their patch.
    for (unsigned i = 0; i < size; ++i) {
        if (patch[i] != (enable ? hook.backup[i] : expected[i])) { result.status = PatchChanged; return; }
    }
    DWORD oldProtection;
    if (!VirtualProtect(patch, size, PAGE_EXECUTE_READWRITE, &oldProtection)) {
        result.status = ProtectionChangeFailed; result.error = GetLastError(); return;
    }
    for (unsigned i = 0; i < size; ++i) patch[i] = enable ? expected[i] : hook.backup[i];
    result.patchWritten = 1;
    DWORD unused;
    if (!VirtualProtect(patch, size, oldProtection, &unused)) {
        result.status = ProtectionRestoreFailed; result.error = GetLastError();
    }
    if (!FlushInstructionCache(GetCurrentProcess(), patch, size) && result.status == Success) {
        result.status = CacheFlushFailed; result.error = GetLastError();
    }
}
}

// C linkage and cdecl keep this ABI identical across all managed target frameworks.
#define API extern "C" __declspec(dllexport)
API int __cdecl mh_map_ip(const HookPlan* hook, uint64_t ip, int enable, uint64_t* mapped) noexcept {
    return MapIp(*hook, ip, enable != 0, *mapped) ? 1 : 0;
}

API void __cdecl mh_capture(ThreadEntry* threads, uint32_t count, const HookPlan* hooks,
    uint32_t hookCount, int enable, Result* result) noexcept {
    *result = {};
    Capture(threads, count, hooks, hookCount, enable != 0, *result);
}

API void __cdecl mh_apply(ThreadEntry* threads, uint32_t count, uint32_t* applied, Result* result) noexcept {
    *result = {};
    Apply(threads, count, *applied, *result);
}

API DWORD __cdecl mh_rollback(ThreadEntry* threads, uint32_t applied) noexcept { return Rollback(threads, applied); }

API void __cdecl mh_execute(ThreadEntry* threads, uint32_t count, const HookPlan* hooks,
    uint32_t hookCount, int enable, int writePatch, Result* result) noexcept {
    *result = {};
    if ((writePatch && hookCount != 1) || (count && !threads) || (hookCount && !hooks)) {
        result->status = InvalidInput; result->error = ERROR_INVALID_PARAMETER; return;
    }
    for (uint32_t h = 0; h < hookCount; ++h) {
        if (!hooks[h].target || !hooks[h].trampoline || hooks[h].boundaryCount > MemorySlotSize) {
            result->status = InvalidInput; result->error = ERROR_INVALID_PARAMETER; return;
        }
    }
    for (uint32_t i = 0; i < count; ++i) {
        auto& entry = threads[i];
        entry.suspended = entry.exited = 0;
        if (WaitForSingleObject(entry.thread, 0) == WAIT_OBJECT_0) { entry.exited = 1; continue; }
        if (GetThreadId(entry.thread) == GetCurrentThreadId() || GetProcessIdOfThread(entry.thread) != GetCurrentProcessId()) {
            result->status = InvalidInput; result->error = ERROR_INVALID_PARAMETER; return;
        }
    }
    // Keep everything through the resume loop native. Managed code can wait on a CLR thread we just stopped.
    uint32_t suspended = 0, applied = 0;
    for (; suspended < count; ++suspended) {
        if (threads[suspended].exited) continue;
        if (SuspendThread(threads[suspended].thread) == DWORD(-1)) {
            const auto error = GetLastError();
            if (WaitForSingleObject(threads[suspended].thread, 0) == WAIT_OBJECT_0) { threads[suspended].exited = 1; continue; }
            result->status = SuspendFailed; result->error = error; break;
        }
        threads[suspended].suspended = 1;
    }
    if (result->status == Success) Capture(threads, count, hooks, hookCount, enable != 0, *result);
    if (result->status == Success) Apply(threads, count, applied, *result);
    if (result->status == Success && writePatch) {
        Patch(hooks[0], enable != 0, *result);
        // If bytes changed but protection or cache flush failed, IPs must still match the new bytes.
        if (result->status != Success && !result->patchWritten) result->rollbackError = Rollback(threads, applied);
    }
    // Undo only our suspension. Another caller may already have stopped the same thread.
    // No managed code, callbacks, heap allocation, or exception construction before this completes.
    for (uint32_t i = 0; i < suspended; ++i) {
        if (!threads[i].suspended) continue;
        if (ResumeThread(threads[i].thread) == DWORD(-1)) {
            const auto error = GetLastError();
            if (WaitForSingleObject(threads[i].thread, 0) != WAIT_OBJECT_0 && result->resumeError == 0) result->resumeError = error;
        }
    }
    if (result->resumeError != 0 && result->status == Success) {
        result->status = ResumeFailed; result->error = result->resumeError;
    }
}
