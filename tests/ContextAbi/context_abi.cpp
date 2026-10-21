#include <windows.h>
#include <cstddef>
#include <cstdio>

// Optional independent check against the installed Windows SDK, not a library dependency.

int main() {
#ifdef _WIN64
    static_assert(sizeof(CONTEXT) == 1232);
    static_assert(alignof(CONTEXT) == 16);
    static_assert(offsetof(CONTEXT, ContextFlags) == 48);
    static_assert(offsetof(CONTEXT, Rip) == 248);
    static_assert(offsetof(CONTEXT, Rsp) == 152);
    static_assert(offsetof(CONTEXT, SegCs) == 56);
    static_assert(offsetof(CONTEXT, SegSs) == 66);
    static_assert(offsetof(CONTEXT, EFlags) == 68);
    std::printf("x64 size=%zu alignment=%zu flags=%zu ip=%zu sp=%zu control=0x%lx\n",
        sizeof(CONTEXT), alignof(CONTEXT), offsetof(CONTEXT, ContextFlags), offsetof(CONTEXT, Rip), offsetof(CONTEXT, Rsp), CONTEXT_CONTROL);
#else
    static_assert(sizeof(CONTEXT) == 716);
    static_assert(offsetof(CONTEXT, ContextFlags) == 0);
    static_assert(offsetof(CONTEXT, Eip) == 184);
    static_assert(offsetof(CONTEXT, Ebp) == 180);
    static_assert(offsetof(CONTEXT, Esp) == 196);
    static_assert(offsetof(CONTEXT, SegCs) == 188);
    static_assert(offsetof(CONTEXT, SegSs) == 200);
    static_assert(offsetof(CONTEXT, EFlags) == 192);
    std::printf("x86 size=%zu alignment=%zu flags=%zu ip=%zu sp=%zu control=0x%lx\n",
        sizeof(CONTEXT), alignof(CONTEXT), offsetof(CONTEXT, ContextFlags), offsetof(CONTEXT, Eip), offsetof(CONTEXT, Esp), CONTEXT_CONTROL);
#endif
}
