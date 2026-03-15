# BYOUD — Bring Your Own Unwind Data

BYOUD is a framework for x64 stack spoofing on Windows. It tackles a complete opposite approach from classic stack spoofing, manipulating unwind metadata to hide arbitrary chunks of the call chain in debuggers and EDRs.

For a full technical breakdown of how it works, see the [blog post](https://klezvirus.github.io/posts/Byoud).

---

## Techniques

| # | Name | Description |
|---|---|---|
| 1 | `UNWIND_DATA_TAMPER` | Modifies the target function's `UNWIND_INFO` in place to expand the frame size |
| 2 | `UNWIND_DATA_HIJACK` | Replaces the `UnwindData` RVA of the target's `RUNTIME_FUNCTION` with a donor's |
| 3 | `RT_FUNCTION_HIJACK` | Hijacks an existing `.pdata` entry to cover the shellcode's address range |
| 4 | `RT_FUNCTION_INJECT` | Appends a new `RUNTIME_FUNCTION` and `UNWIND_INFO` to the module's exception directory |
| 5 | `RTFI_JIT_SYSINFORMER` | Registers a dynamic `RUNTIME_FUNCTION` via `RtlAddFunctionTable` with cache bypass — visible to SystemInformer |
| 6 | `RTFI_JIT_WINDBG` | Same as above with additional `LdrpInvertedFunctionTable` manipulation — visible to WinDbg |
| 7 | `RTFI_JIT_NORMAL_VA` | Registers a dynamic `RUNTIME_FUNCTION` for shellcode in a plain `VirtualAlloc`'d region |

Techniques 1–4 and 7 work correctly regardless of `/GS` compilation settings. Techniques 5 and 6 have known issues when the calling DLL is compiled with stack cookies. Compile with `/GS-` to avoid this.

---

## Components

**`byoud.dll`** — the framework. Exposes `ShieldedExecution` (runs a technique end-to-end) and `CallGate` (the assembly stub copied into target modules).

**`udinject.exe`** — test harness for exercising the framework, inspecting stack traces, and validating unwind behavior across techniques.

---

For everything else, see the [blog post](https://klezvirus.github.io/posts/Byoud/).

## References and Acknowledgements

* [namazso](https://x.com/namazso) because his original work on stack spoofing has laid the groundwork for all current research on the topic
* [Gabriel Landau](https://x.com/GabrielLandau) for the shadow stack analysis research
* [Alex Ionescu](https://x.com/aionescu) and [Yarden Shafir](https://x.com/yarden_shafir) for their CET internals work
