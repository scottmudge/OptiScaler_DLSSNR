#pragma once

#include <Windows.h>

namespace MfgUnlock
{
// Unlocks DLSS multi-frame generation (3x-6x) on Ada (RTX 40) by patching, in
// process memory only, the DLSS-G NGX snippet (nvngx_dlssg.dll) and the
// Streamline DLSS-G plugin (sl.dlss_g.dll) that OptiScaler loads from its
// bundled `streamline/` folder. The game itself needs no Streamline; OptiScaler
// supplies its own, and that is what is patched here.
//
//   1. Arch gates (nvngx_dlssg.dll): rewrite the two `cmp <r32>, 0x1B0`
//      (Blackwell GB20x) compares to `cmp <r32>, 0` so the snippet advertises
//      DLSSG.MultiFrameCountMax = 5 and sets its runtime multi-frame flag. This
//      is the actual enable; without it the runtime clamps to 1 generated frame
//      (2x) and rejects any higher count.
//   2. Temporal / midpoint fix (nvngx_dlssg.dll): the interpolation kernel blends
//      the two source frames with a compiled-in 0.5, so every generated frame
//      lands at the temporal midpoint (4x = three identical half-way frames).
//      The kernel's sm_89 PTX is rebuilt so the blend weight comes from the
//      per-frame temporal parameter t = index/(count+1); the precompiled sm_89
//      cubin is dropped to force a JIT of the edit; the kernel descriptor slots
//      are repointed at the rebuilt fatbin.
//   3. Flip metering (sl.dlss_g.dll): Ada has no hardware flip metering, so 3x+
//      would freeze presentation. The plugin's flip-metering flag is pinned to
//      the value its own software-fallback path writes, forcing the RSYNC
//      software pacer for smooth, low-latency output.
//   4. Frame ceiling (sl.dlss_g.dll): stop the plugin from clamping its compiled
//      maximum to a stale cached NGX device value (cmovb edx,ecx -> cmovb edx,edx).
//
// NGX verifies the snippet's Authenticode signature at load time, so on-disk
// edits make frame generation disappear entirely. Everything here is applied to
// the mapped image and reverted on unload -- never to the file.
//
// Apply()/EnsureApplied() are idempotent (each module is patched once) and gated
// on [Config] FGMfgUnlock. They must be called early: the arch gate has to land
// before slInit builds the NGX feature, while the plugin is only available after.
// Restore() undoes every patch.
void Apply();
void EnsureApplied();
void Restore();

// True once every applicable patch has landed (diagnostics).
bool IsApplied();

// Returns true exactly once, on the first call after the patches have first been
// applied. Lets the caller re-read numFramesToGenerateMax so the MFG count
// selector becomes available without a swapchain recreation.
bool ConsumeJustApplied();

// Live per-patch status for the UI so the user can confirm what actually landed.
struct Status
{
    bool enabled = false;      // FGMfgUnlock opt-in is on
    bool archGates = false;    // snippet arch gates rewritten (cap raised to 5)
    bool temporal = false;     // midpoint fatbin rebuilt + descriptors repointed
    bool flipMeter = false;    // plugin flip-metering pinned (software RSYNC pacing)
    bool ceiling = false;      // plugin frame ceiling stopped
    int maxGenerated = 1;      // 5 generated frames (6x) once arch gates land, else 1 (2x)
};
Status GetStatus();
}
