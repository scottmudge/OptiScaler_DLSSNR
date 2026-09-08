#include "pch.h"

#include <atomic>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

#include "mfg_unlock.h"

namespace
{

constexpr uint32_t kFatbinMagic = 0xBA55ED50u;
constexpr uint16_t kFatbinOuterHeader = 16;
constexpr uint16_t kPtxKind = 1;
constexpr uint32_t kAdaArch = 89;
constexpr uint64_t kUncompressedFlags = 0x41;
constexpr uint32_t kBlackwell = 0x1B0;

// 310.9.0 temporal (midpoint) kernel profile, verified against the bundled
// nvngx_dlssg.dll: the sm_89 PTX is exactly 99626 bytes, the entry is
// Kernel_EstimateIntermMvecsScatter, the descriptor string is
// EstimateIntermMvecsScatter, and the descriptor holds the entry-name pointer at
// +0x10 and the descriptor-name pointer at -0x08 relative to the fatbin pointer.
constexpr size_t kTemporalPtxBytes = 99626;
constexpr const char* kTemporalEntryName = "Kernel_EstimateIntermMvecsScatter";
constexpr const char* kTemporalDescName = "EstimateIntermMvecsScatter";
constexpr ptrdiff_t kEntryNameOffset = 0x10;
constexpr ptrdiff_t kDescNameOffset = -0x08;

constexpr size_t kExpectedMidpoints = 104;
constexpr const char kJoinLabel[] = "$L__BB0_3:";
constexpr const char kMidpointBits[] = "0f3F000000";
constexpr const char kMulPrefix[] = "mul.ftz.f32 ";
constexpr const char kCurrToPrev[] = "%f136";
constexpr const char kPrevToCurr[] = "%f134";

constexpr const char kFlipMarker[] = "FG1 DLL has been detected";

uint16_t ReadU16(const uint8_t* p)
{
    uint16_t v = 0;
    std::memcpy(&v, p, sizeof(v));
    return v;
}
uint32_t ReadU32(const uint8_t* p)
{
    uint32_t v = 0;
    std::memcpy(&v, p, sizeof(v));
    return v;
}
uint64_t ReadU64(const uint8_t* p)
{
    uint64_t v = 0;
    std::memcpy(&v, p, sizeof(v));
    return v;
}

bool ModuleImage(HMODULE mod, uint8_t*& base, IMAGE_NT_HEADERS64*& nt, size_t& image_size)
{
    if (mod == nullptr)
        return false;
    base = reinterpret_cast<uint8_t*>(mod);
    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
        return false;
    nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE)
        return false;
    if (nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
        return false;
    image_size = nt->OptionalHeader.SizeOfImage;
    return true;
}

// Plain LZ4 block format: token high nibble = literal run, low nibble = match
// length - 4, 16-bit little-endian back offset, 0xFF continuation bytes.
bool Lz4BlockDecompress(const uint8_t* src, size_t src_size, uint8_t* dst, size_t dst_size)
{
    size_t in = 0;
    size_t out = 0;
    while (in < src_size)
    {
        const uint8_t token = src[in++];
        size_t literals = token >> 4;
        if (literals == 15)
        {
            uint8_t ext = 0;
            do
            {
                if (in >= src_size)
                    return false;
                ext = src[in++];
                literals += ext;
            } while (ext == 0xFF);
        }
        if (literals > src_size - in || literals > dst_size - out)
            return false;
        std::memcpy(dst + out, src + in, literals);
        in += literals;
        out += literals;
        if (in == src_size)
            break;
        if (src_size - in < 2)
            return false;
        const size_t back = static_cast<size_t>(src[in]) | (static_cast<size_t>(src[in + 1]) << 8);
        in += 2;
        if (back == 0 || back > out)
            return false;
        size_t match = 4 + (token & 0x0F);
        if ((token & 0x0F) == 15)
        {
            uint8_t ext = 0;
            do
            {
                if (in >= src_size)
                    return false;
                ext = src[in++];
                match += ext;
            } while (ext == 0xFF);
        }
        if (match > dst_size - out)
            return false;
        for (size_t i = 0; i < match; ++i)
            dst[out + i] = dst[out + i - back];
        out += match;
    }
    return in == src_size && out == dst_size;
}

// ---------------------------------------------------------------------------
// Code-patch bookkeeping so Restore() can put every byte back exactly.
// ---------------------------------------------------------------------------
struct CodePatch
{
    uint8_t* address = nullptr;
    std::vector<uint8_t> original;
};
struct PointerPatch
{
    uint64_t* slot = nullptr;
    uint64_t original = 0;
};

std::atomic<bool> g_applied{false};
std::atomic<bool> g_justApplied{false};
bool g_snippetPatched = false;
bool g_pluginPatched = false;
bool g_archGatesOk = false;
bool g_temporalOk = false;
bool g_flipMeterOk = false;
bool g_ceilingOk = false;
bool g_drsClampOk = false;
void* g_midpointAlloc = nullptr;
std::vector<CodePatch> g_codePatches;
std::vector<PointerPatch> g_pointerPatches;

bool WritePatch(uint8_t* at, const uint8_t* bytes, size_t length)
{
    if (at == nullptr || length == 0)
        return false;
    DWORD old_protect = 0;
    if (VirtualProtect(at, length, PAGE_EXECUTE_READWRITE, &old_protect) == 0)
        return false;
    CodePatch patch;
    patch.address = at;
    patch.original.assign(at, at + length);
    std::memcpy(at, bytes, length);
    DWORD ignored = 0;
    VirtualProtect(at, length, old_protect, &ignored);
    FlushInstructionCache(GetCurrentProcess(), at, length);
    g_codePatches.push_back(std::move(patch));
    return true;
}

void RestoreCodePatches()
{
    for (const auto& patch : g_codePatches)
    {
        if (patch.address == nullptr)
            continue;
        DWORD old_protect = 0;
        if (VirtualProtect(patch.address, patch.original.size(), PAGE_EXECUTE_READWRITE, &old_protect) != 0)
        {
            std::memcpy(patch.address, patch.original.data(), patch.original.size());
            DWORD ignored = 0;
            VirtualProtect(patch.address, patch.original.size(), old_protect, &ignored);
            FlushInstructionCache(GetCurrentProcess(), patch.address, patch.original.size());
        }
    }
    g_codePatches.clear();
}

void RestorePointerPatches()
{
    for (const auto& patch : g_pointerPatches)
    {
        if (patch.slot == nullptr)
            continue;
        DWORD old_protect = 0;
        if (VirtualProtect(patch.slot, sizeof(uint64_t), PAGE_READWRITE, &old_protect) == 0)
            continue;
        *patch.slot = patch.original;
        DWORD ignored = 0;
        VirtualProtect(patch.slot, sizeof(uint64_t), old_protect, &ignored);
    }
    g_pointerPatches.clear();
    if (g_midpointAlloc != nullptr)
    {
        VirtualFree(g_midpointAlloc, 0, MEM_RELEASE);
        g_midpointAlloc = nullptr;
    }
}

// ---------------------------------------------------------------------------
// 1. Arch gates (nvngx_dlssg.dll)
// ---------------------------------------------------------------------------
bool PatchNgxArchGates(HMODULE mod)
{
    uint8_t* base = nullptr;
    IMAGE_NT_HEADERS64* nt = nullptr;
    size_t image_size = 0;
    if (!ModuleImage(mod, base, nt, image_size))
        return false;

    const uint8_t imm[4] = { 0xB0, 0x01, 0x00, 0x00 };
    int eaxSites = 0;
    int regSites = 0;
    uint8_t* eaxSite = nullptr;
    uint8_t* regSite = nullptr;

    const auto* section = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++section)
    {
        if ((section->Characteristics & IMAGE_SCN_MEM_EXECUTE) == 0)
            continue;
        uint8_t* start = base + section->VirtualAddress;
        const size_t size = section->Misc.VirtualSize;
        if (size < 6)
            continue;
        for (size_t off = 0; off + 6 <= size; ++off)
        {
            // 3D id32 -> cmp eax, 0x1B0
            if (start[off] == 0x3D && std::memcmp(start + off + 1, imm, 4) == 0)
            {
                ++eaxSites;
                eaxSite = start + off + 1;
                continue;
            }
            // 81 /7 modrm(id=11,reg=111) id32 -> cmp r32, 0x1B0 (modrm 0xF8-0xFF)
            if (start[off] == 0x81 && start[off + 1] >= 0xF8 && start[off + 1] <= 0xFF &&
                std::memcmp(start + off + 2, imm, 4) == 0)
            {
                ++regSites;
                regSite = start + off + 2;
            }
        }
    }

    if (eaxSites != 1 || regSites != 1)
    {
        LOG_WARN("MfgUnlock: arch-gate scan found {} 'cmp eax,0x1B0' and {} 'cmp r32,0x1B0' (expected 1 of "
                 "each); this nvngx_dlssg.dll is not a known build, leaving the arch gates alone", eaxSites,
                 regSites);
        return false;
    }

    const uint32_t zero = 0;
    if (!WritePatch(eaxSite, reinterpret_cast<const uint8_t*>(&zero), 4))
    {
        LOG_ERROR("MfgUnlock: could not make the arch gate (cmp eax) writable");
        return false;
    }
    if (!WritePatch(regSite, reinterpret_cast<const uint8_t*>(&zero), 4))
    {
        LOG_ERROR("MfgUnlock: could not make the arch gate (cmp r32) writable");
        return false;
    }

    LOG_INFO("MfgUnlock: rewrote both arch gates (cmp r32,0x1B0 -> cmp r32,0) in nvngx_dlssg.dll; "
             "MultiFrameCountMax now reports 5");
    return true;
}

// ---------------------------------------------------------------------------
// 2. Temporal / midpoint kernel (nvngx_dlssg.dll)
// ---------------------------------------------------------------------------

// Find the sm_89 PTX entry offset within a fatbin by walking its entry list.
bool FindAdaPtxEntry(const uint8_t* fat, size_t fat_size, size_t& entry_offset)
{
    if (fat_size < kFatbinOuterHeader || ReadU32(fat) != kFatbinMagic)
        return false;
    if (ReadU16(fat + 6) != kFatbinOuterHeader)
        return false;
    const uint64_t declared = ReadU64(fat + 8);
    if (declared + kFatbinOuterHeader != fat_size)
        return false;

    size_t p = kFatbinOuterHeader;
    while (p + 64 <= fat_size)
    {
        const uint32_t kind = ReadU16(fat + p);
        const uint32_t hdr = ReadU32(fat + p + 4);
        const uint64_t payload = ReadU64(fat + p + 8);
        if (hdr < 64 || payload == 0)
            return false;
        if (p + hdr + payload > fat_size)
            return false;
        if (kind == kPtxKind && ReadU32(fat + p + 28) == kAdaArch)
        {
            entry_offset = p;
            return true;
        }
        p += hdr + payload;
    }
    return false;
}

bool FindAdaPtxRawSize(const uint8_t* fat, size_t fat_size, uint64_t& raw)
{
    size_t entry = 0;
    if (!FindAdaPtxEntry(fat, fat_size, entry))
        return false;
    raw = ReadU64(fat + entry + 56);
    return raw != 0;
}

bool PointsToCString(const uint8_t* base, size_t image_size, uint64_t value, const char* expected)
{
    const auto start = reinterpret_cast<uintptr_t>(base);
    if (value < start || value >= start + image_size)
        return false;
    const char* s = reinterpret_cast<const char*>(value);
    const size_t len = std::strlen(expected);
    if (value + len + 1 > start + image_size)
        return false;
    return std::memcmp(s, expected, len + 1) == 0;
}

// Decompress the Ada PTX, rewrite the blend weights, re-emit a truncated fatbin
// that ends right after the sm_89 PTX entry (dropping the precompiled cubin to
// force a JIT of the edited PTX).
bool BuildTemporalFatbin(const uint8_t* fat, size_t fat_size, std::vector<uint8_t>& out, std::string& why)
{
    size_t entry = 0;
    if (!FindAdaPtxEntry(fat, fat_size, entry))
    {
        why = "no sm_89 PTX entry";
        return false;
    }

    const uint32_t hdr = ReadU32(fat + entry + 4);
    const uint32_t compressed = ReadU32(fat + entry + 16);
    const uint64_t raw = ReadU64(fat + entry + 56);
    if (compressed == 0 || raw == 0 || raw > (8u << 20))
    {
        why = "PTX entry is not compressed as expected";
        return false;
    }
    if (raw != kTemporalPtxBytes)
    {
        why = "temporal PTX is not the expected 310.9.0 size";
        return false;
    }

    std::vector<uint8_t> ptx(raw);
    if (!Lz4BlockDecompress(fat + entry + hdr, compressed, ptx.data(), ptx.size()))
    {
        why = "LZ4 decompression failed";
        return false;
    }

    const std::string entry_signature = std::string(".entry ") + kTemporalEntryName + "(";
    const std::string parameter_name = std::string(kTemporalEntryName) + "_param_0";
    const std::string parameter_signature = std::string(".param .align 8 .b8 ") + parameter_name + "[144]";
    const std::string ptx_text(reinterpret_cast<const char*>(ptx.data()), ptx.size());
    if (ptx_text.find(entry_signature) == std::string::npos ||
        ptx_text.find(parameter_signature) == std::string::npos ||
        ptx_text.find(".reg .f32 %f<1362>;") == std::string::npos)
    {
        why = "temporal kernel signature changed";
        return false;
    }

    const char* begin = reinterpret_cast<const char*>(ptx.data());
    const size_t n = ptx.size();
    const size_t label_len = sizeof(kJoinLabel) - 1;
    size_t label = SIZE_MAX;
    for (size_t i = 0; i + label_len <= n; ++i)
    {
        if (std::memcmp(begin + i, kJoinLabel, label_len) != 0)
            continue;
        if (label != SIZE_MAX)
        {
            why = "join label is not unique";
            return false;
        }
        label = i;
    }
    if (label == SIZE_MAX)
    {
        why = "join label not found";
        return false;
    }
    size_t insertion = label + label_len;
    while (insertion < n && begin[insertion] != '\n')
        ++insertion;
    if (insertion >= n)
    {
        why = "join label has no line end";
        return false;
    }
    ++insertion;

    // Every midpoint constant that terminates a `mul.ftz.f32 ...;` line.
    const size_t mid_len = sizeof(kMidpointBits) - 1;
    const size_t mul_len = sizeof(kMulPrefix) - 1;
    std::vector<size_t> marks;
    marks.reserve(kExpectedMidpoints);
    for (size_t i = 0; i + mid_len < n; ++i)
    {
        if (std::memcmp(begin + i, kMidpointBits, mid_len) != 0)
            continue;
        if (begin[i + mid_len] != ';')
            continue;
        size_t line = i;
        while (line > 0 && begin[line - 1] != '\n')
            --line;
        if (i - line < mul_len)
            continue;
        if (std::memcmp(begin + line, kMulPrefix, mul_len) != 0)
            continue;
        marks.push_back(i);
    }
    if (marks.size() != kExpectedMidpoints)
    {
        why = "wrong midpoint count";
        return false;
    }
    if (marks.front() <= insertion)
    {
        why = "first midpoint precedes the injection point";
        return false;
    }

    const std::string temporal_input =
        ("ld.param.f32 %f134, [" + parameter_name + "+32];\r\n"
         "mov.f32 %f135, 0f3F800000;\r\n"
         "sub.ftz.f32 %f136, %f135, %f134;\r\n");

    std::vector<uint8_t> patched;
    patched.reserve(n + temporal_input.size());
    auto append = [&patched](const void* p, size_t bytes) {
        const auto* b = static_cast<const uint8_t*>(p);
        patched.insert(patched.end(), b, b + bytes);
    };
    append(ptx.data(), insertion);
    append(temporal_input.data(), temporal_input.size());
    size_t src = insertion;
    const size_t half = kExpectedMidpoints / 2;
    for (size_t i = 0; i < marks.size(); ++i)
    {
        append(ptx.data() + src, marks[i] - src);
        const char* scale = (i < half) ? kCurrToPrev : kPrevToCurr;
        append(scale, 5);
        src = marks[i] + mid_len;
    }
    append(ptx.data() + src, n - src);

    const size_t padded = (patched.size() + 7) & ~size_t{7};
    const size_t final_size = entry + hdr + padded;

    out.assign(fat, fat + entry + hdr);
    out.resize(final_size, 0);
    std::memcpy(out.data() + entry + hdr, patched.data(), patched.size());

    const uint64_t payload64 = padded;
    const uint32_t zero32 = 0;
    const uint64_t zero64 = 0;
    std::memcpy(out.data() + entry + 8, &payload64, sizeof(payload64));
    std::memcpy(out.data() + entry + 16, &zero32, sizeof(zero32));
    std::memcpy(out.data() + entry + 40, &kUncompressedFlags, sizeof(kUncompressedFlags));
    std::memcpy(out.data() + entry + 56, &zero64, sizeof(zero64));
    const uint64_t outer = final_size - kFatbinOuterHeader;
    std::memcpy(out.data() + 8, &outer, sizeof(outer));
    return true;
}

bool PatchNgxMidpoint(HMODULE mod)
{
    uint8_t* base = nullptr;
    IMAGE_NT_HEADERS64* nt = nullptr;
    size_t image_size = 0;
    if (!ModuleImage(mod, base, nt, image_size))
        return false;
    const auto start = reinterpret_cast<uintptr_t>(base);

    // Find descriptor slots: an 8-byte pointer to the temporal fatbin, with the
    // entry/descriptor names at their version-specific relative offsets. The
    // module carries eight such descriptors in separate tables; we cannot tell
    // which the runtime will pick, so all of them are redirected.
    std::vector<uint64_t*> slots;
    const uint8_t* fat = nullptr;
    size_t fat_size = 0;

    const auto* section = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++section)
    {
        if ((section->Characteristics & IMAGE_SCN_MEM_READ) == 0)
            continue;
        if ((section->Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0)
            continue;
        uint8_t* sec = base + section->VirtualAddress;
        const size_t size = section->Misc.VirtualSize;
        for (size_t off = 0; off + sizeof(uint64_t) <= size; off += sizeof(uint64_t))
        {
            uint64_t value = 0;
            std::memcpy(&value, sec + off, sizeof(value));
            if (value < start || value >= start + image_size)
                continue;
            const auto* candidate = reinterpret_cast<const uint8_t*>(value);
            if (ReadU32(candidate) != kFatbinMagic)
                continue;
            const uint64_t declared = ReadU64(candidate + 8);
            const size_t total = static_cast<size_t>(declared) + kFatbinOuterHeader;
            if (total < 1024 || total > (16u << 20))
                continue;
            if (value + total > start + image_size)
                continue;

            uint64_t raw = 0;
            if (!FindAdaPtxRawSize(candidate, total, raw) || raw != kTemporalPtxBytes)
                continue;

            const uint8_t* slot = sec + off;
            const uintptr_t slotAddr = reinterpret_cast<uintptr_t>(slot);
            uint64_t entry_name = 0;
            uint64_t desc_name = 0;
            if (slotAddr + kEntryNameOffset < start || slotAddr + kEntryNameOffset + 8 > start + image_size)
                continue;
            if (slotAddr + kDescNameOffset < start || slotAddr + kDescNameOffset + 8 > start + image_size)
                continue;
            std::memcpy(&entry_name, slot + kEntryNameOffset, sizeof(entry_name));
            std::memcpy(&desc_name, slot + kDescNameOffset, sizeof(desc_name));
            if (!PointsToCString(base, image_size, entry_name, kTemporalEntryName) ||
                !PointsToCString(base, image_size, desc_name, kTemporalDescName))
                continue;

            if (fat == nullptr)
            {
                fat = candidate;
                fat_size = total;
            }
            else if (candidate != fat)
            {
                continue; // a second temporal-looking kernel; leave it alone
            }
            slots.push_back(reinterpret_cast<uint64_t*>(const_cast<uint8_t*>(slot)));
        }
    }

    if (fat == nullptr || slots.empty())
    {
        LOG_WARN("MfgUnlock: no supported temporal-kernel descriptor found in nvngx_dlssg.dll (310.9.0 "
                 "expected); skipping the midpoint fix -- generated frames would all land at the midpoint");
        return false;
    }

    std::vector<uint8_t> rebuilt;
    std::string why;
    if (!BuildTemporalFatbin(fat, fat_size, rebuilt, why))
    {
        LOG_WARN("MfgUnlock: temporal fatbin rebuild failed -- {}", why);
        return false;
    }

    void* mem = VirtualAlloc(nullptr, rebuilt.size(), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (mem == nullptr)
    {
        LOG_ERROR("MfgUnlock: allocation for the temporal-corrected fatbin failed");
        return false;
    }
    std::memcpy(mem, rebuilt.data(), rebuilt.size());

    for (uint64_t* slot : slots)
    {
        DWORD old_protect = 0;
        if (VirtualProtect(slot, sizeof(uint64_t), PAGE_READWRITE, &old_protect) == 0)
            continue;
        g_pointerPatches.push_back({ slot, *slot });
        *slot = reinterpret_cast<uint64_t>(mem);
        DWORD ignored = 0;
        VirtualProtect(slot, sizeof(uint64_t), old_protect, &ignored);
    }

    if (g_pointerPatches.empty())
    {
        VirtualFree(mem, 0, MEM_RELEASE);
        LOG_ERROR("MfgUnlock: no temporal descriptor slot was writable");
        return false;
    }

    g_midpointAlloc = mem;
    LOG_INFO("MfgUnlock: redirected {} {} descriptor(s) from a {}-byte fatbin to a {}-byte "
             "temporal-corrected rebuild", slots.size(), kTemporalDescName, fat_size, rebuilt.size());
    return true;
}

// ---------------------------------------------------------------------------
// 3. Flip metering (sl.dlss_g.dll)
// ---------------------------------------------------------------------------
bool PatchSlFlipMetering(HMODULE mod)
{
    uint8_t* base = nullptr;
    IMAGE_NT_HEADERS64* nt = nullptr;
    size_t image_size = 0;
    if (!ModuleImage(mod, base, nt, image_size))
        return false;

    // 1. Is this the DLSS-G plugin? The marker string identifies it.
    const size_t marker_len = sizeof(kFlipMarker) - 1;
    const uint8_t* marker = nullptr;
    const auto* section = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections && marker == nullptr; ++i, ++section)
    {
        if ((section->Characteristics & IMAGE_SCN_MEM_READ) == 0)
            continue;
        uint8_t* start = base + section->VirtualAddress;
        const size_t size = section->Misc.VirtualSize;
        if (size < marker_len)
            continue;
        for (size_t off = 0; off + marker_len <= size; ++off)
        {
            if (std::memcmp(start + off, kFlipMarker, marker_len) == 0)
            {
                marker = start + off;
                break;
            }
        }
    }
    if (marker == nullptr)
        return false;

    // 2. Find the code that references the marker, then read the (offset, value)
    //    its own fallback writes: C6 /r disp32 imm8 == mov byte ptr [reg+disp32],
    //    imm8. That pair IS the wanted state, whatever its polarity.
    unsigned int want_offset = 0;
    int want_value = -1;
    section = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections && want_value < 0; ++i, ++section)
    {
        if ((section->Characteristics & IMAGE_SCN_MEM_EXECUTE) == 0)
            continue;
        uint8_t* start = base + section->VirtualAddress;
        const size_t size = section->Misc.VirtualSize;
        if (size < 8)
            continue;
        for (size_t off = 0; off + 8 <= size && want_value < 0; ++off)
        {
            // lea reg, [rip+disp32] pointing at the marker string
            if (!(start[off] == 0x48 || start[off] == 0x4C))
                continue;
            if (start[off + 1] != 0x8D)
                continue;
            if ((start[off + 2] & 0xC7) != 0x05)
                continue;
            int disp = 0;
            std::memcpy(&disp, start + off + 3, sizeof(disp));
            if (start + off + 7 + disp != marker)
                continue;

            const size_t window = 0x200;
            const size_t limit = (off + window < size) ? (off + window) : size;
            for (size_t w = off; w + 7 <= limit; ++w)
            {
                if (start[w] != 0xC6)
                    continue;
                if (start[w + 1] < 0x80 || start[w + 1] > 0xBF)
                    continue;
                unsigned int field = 0;
                std::memcpy(&field, start + w + 2, sizeof(field));
                const unsigned char imm = start[w + 6];
                if (field <= 0x100 || field >= 0x20000)
                    continue;
                if (imm > 1)
                    continue;
                want_offset = field;
                want_value = imm;
                break;
            }
        }
    }

    if (want_value < 0)
    {
        LOG_WARN("MfgUnlock: located the DLSS-G plugin but could not read its flip-metering fallback "
                 "state; leaving it alone");
        return false;
    }

    // 3. Pin the field to that value everywhere it is written.
    const unsigned char opposite = static_cast<unsigned char>(1 - want_value);
    size_t flipped = 0;
    section = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++section)
    {
        if ((section->Characteristics & IMAGE_SCN_MEM_EXECUTE) == 0)
            continue;
        uint8_t* start = base + section->VirtualAddress;
        const size_t size = section->Misc.VirtualSize;
        if (size < 7)
            continue;
        for (size_t off = 0; off + 7 <= size; ++off)
        {
            // C6 /0 disp32 imm8 -- flip the immediate.
            if (start[off] == 0xC6)
            {
                if (start[off + 1] < 0x80 || start[off + 1] > 0xBF)
                    continue;
                unsigned int field = 0;
                std::memcpy(&field, start + off + 2, sizeof(field));
                if (field != want_offset)
                    continue;
                if (start[off + 6] != opposite)
                    continue;
                const unsigned char imm = static_cast<unsigned char>(want_value);
                if (WritePatch(start + off + 6, &imm, 1))
                    ++flipped;
                continue;
            }

            // 40 88 /r disp32 -- rewrite the whole store into the C6 form.
            if (start[off] != 0x40 || start[off + 1] != 0x88)
                continue;
            const unsigned char modrm = start[off + 2];
            if (modrm < 0x80 || modrm > 0xBF)
                continue;
            const unsigned char rm = static_cast<unsigned char>(modrm & 7);
            if (rm == 4)
                continue;
            unsigned int field = 0;
            std::memcpy(&field, start + off + 3, sizeof(field));
            if (field != want_offset)
                continue;

            unsigned char replacement[7] = { 0xC6, static_cast<unsigned char>(0x80 | rm),
                                             0,    0,
                                             0,    0,
                                             static_cast<unsigned char>(want_value) };
            std::memcpy(replacement + 2, &want_offset, sizeof(want_offset));
            if (WritePatch(start + off, replacement, sizeof(replacement)))
                ++flipped;
        }
    }

    if (flipped == 0)
    {
        LOG_WARN("MfgUnlock: flip-metering field +0x{:X} derived but nothing writes it in a patchable "
                 "form; leaving it alone", want_offset);
        return false;
    }

    LOG_INFO("MfgUnlock: forced flip-metering off in sl.dlss_g.dll -- field +0x{:X} pinned to {} at {} "
             "site(s); multi-frame now paces in software (RSYNC)", want_offset, want_value, flipped);
    return true;
}

// ---------------------------------------------------------------------------
// 4. Frame ceiling (sl.dlss_g.dll)
// ---------------------------------------------------------------------------
bool PatchSlFrameCeiling(HMODULE mod)
{
    uint8_t* base = nullptr;
    IMAGE_NT_HEADERS64* nt = nullptr;
    size_t image_size = 0;
    if (!ModuleImage(mod, base, nt, image_size))
        return false;

    // BA xx 00 00 00  3B CA  0F 42 D1
    // mov edx,xx ; cmp ecx,edx ; cmovb edx,ecx
    const uint8_t tail[5] = { 0x3B, 0xCA, 0x0F, 0x42, 0xD1 };
    uint8_t* found = nullptr;
    size_t hits = 0;
    const auto* section = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++section)
    {
        if ((section->Characteristics & IMAGE_SCN_MEM_EXECUTE) == 0)
            continue;
        uint8_t* start = base + section->VirtualAddress;
        const size_t size = section->Misc.VirtualSize;
        if (size < 10)
            continue;
        for (size_t off = 0; off + 10 <= size; ++off)
        {
            if (start[off] != 0xBA)
                continue;
            if (start[off + 2] != 0 || start[off + 3] != 0 || start[off + 4] != 0)
                continue;
            if (std::memcmp(start + off + 5, tail, sizeof(tail)) != 0)
                continue;
            const unsigned char ceiling = start[off + 1];
            if (ceiling == 0 || ceiling > 8)
                continue;
            if (found == nullptr)
                found = start + off;
            ++hits;
        }
    }

    if (hits != 1 || found == nullptr)
    {
        LOG_WARN("MfgUnlock: found {} frame-count clamps in the DLSS-G plugin (expected 1); leaving them "
                 "alone", hits);
        return false;
    }

    // cmovb edx,ecx -> cmovb edx,edx: same three-byte instruction, no lowering.
    // The ModRM byte is the last byte of the 10-byte sequence (found+9).
    const uint8_t modrmFix = 0xD2;
    if (WritePatch(found + 9, &modrmFix, 1))
    {
        LOG_INFO("MfgUnlock: stopped the DLSS-G plugin from lowering its compiled ceiling of {} generated "
                 "frame(s) ({}x) to a stale cached NGX value", found[1], found[1] + 1);
        return true;
    }
    LOG_WARN("MfgUnlock: could not patch the frame-count ceiling");
    return false;
}

// ---------------------------------------------------------------------------
// 5. DRS "max generated frames" clamp (sl.dlss_g.dll)
// ---------------------------------------------------------------------------
// The plugin computes the effective max as min(NGX MultiFrameCountMax, 5, DRS
// key 0x104D6667). On a stock machine the DRS key reads 0 (absent) and drops
// out, but the NVIDIA App can write it (here it was 1), which clamps the max to
// 1 and silently caps MFG at 2x no matter what the app requests. The clamp is
// the `je` that skips the `max = min(DRS, max)` sequence when the DRS value is
// absent; making it unconditional keeps the DRS override from limiting us.
//
// Anchor: the unique 15-byte min-op that performs `max = min(DRS, max)`:
//   41 8B 17   mov  edx,[r15]
//   39 10      cmp  [rax],edx
//   4C 0F 42 C0 cmovb r8,rax
//   41 8B 00   mov  eax,[r8]
//   41 89 07   mov  [r15],eax
// The `je` that guards this block sits 21 bytes before it.
bool PatchSlDrsClamp(HMODULE mod)
{
    uint8_t* base = nullptr;
    IMAGE_NT_HEADERS64* nt = nullptr;
    size_t image_size = 0;
    if (!ModuleImage(mod, base, nt, image_size))
        return false;

    const uint8_t sig[15] = { 0x41, 0x8B, 0x17, 0x39, 0x10,
                              0x4C, 0x0F, 0x42, 0xC0, 0x41,
                              0x8B, 0x00, 0x41, 0x89, 0x07 };
    const size_t sig_len = sizeof(sig);
    const size_t je_offset = 21; // distance from the guarded je to the anchor

    uint8_t* found = nullptr;
    size_t hits = 0;
    const auto* section = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++section)
    {
        if ((section->Characteristics & IMAGE_SCN_MEM_EXECUTE) == 0)
            continue;
        uint8_t* start = base + section->VirtualAddress;
        const size_t size = section->Misc.VirtualSize;
        if (size < je_offset + sig_len)
            continue;
        for (size_t off = je_offset; off + sig_len <= size; ++off)
        {
            if (std::memcmp(start + off, sig, sig_len) != 0)
                continue;
            if (found == nullptr)
                found = start + off;
            ++hits;
        }
    }

    if (hits != 1 || found == nullptr)
    {
        LOG_WARN("MfgUnlock: found {} DRS max-clamp anchors in sl.dlss_g.dll (expected 1); leaving the "
                 "DRS clamp alone", hits);
        return false;
    }

    uint8_t* je = found - je_offset;
    // The guard must be a near `je rel32` (0F 84 <disp32>), 6 bytes long.
    if (je[0] != 0x0F || je[1] != 0x84)
    {
        LOG_WARN("MfgUnlock: the DRS clamp guard is not the expected `je rel32`; leaving it alone");
        return false;
    }
    int32_t je_disp = 0;
    std::memcpy(&je_disp, je + 2, sizeof(je_disp));
    const int32_t target = static_cast<int32_t>(je - base) + 6 + je_disp;

    // Rewrite the 6-byte `je` as an unconditional near `jmp rel32` (5 bytes) + NOP.
    const int32_t jmp_disp = target - (static_cast<int32_t>(je - base) + 5);
    uint8_t replacement[6];
    replacement[0] = 0xE9;
    std::memcpy(replacement + 1, &jmp_disp, 4);
    replacement[5] = 0x90;

    if (WritePatch(je, replacement, sizeof(replacement)))
    {
        LOG_INFO("MfgUnlock: removed the DRS 'max generated frames' clamp in sl.dlss_g.dll (je->jmp); "
                 "the driver profile can no longer cap MFG to 2x");
        return true;
    }
    LOG_WARN("MfgUnlock: could not patch the DRS max-clamp guard");
    return false;
}

bool MfgUnlockEnabled()
{
    // Gate on the user's opt-in only. The DLSSG module handles below are only
    // non-null when OptiScaler has loaded its own Streamline / DLSSG stack, so an
    // enabled flag with no loaded modules is a no-op. We deliberately do NOT also
    // require activeFgOutput==DLSSG here: the arch gate must be patched as early
    // as possible (before slInit builds the NGX feature), which can be before the
    // FG output is marked active.
    return Config::Instance()->FGMfgUnlock.value_or_default();
}

} // namespace

namespace MfgUnlock
{

void Apply()
{
    if (!MfgUnlockEnabled())
        return;

    auto* state = &State::Instance();
    HMODULE snippet = state->optiDLSSG != nullptr ? state->optiDLSSG : GetModuleHandleW(L"nvngx_dlssg.dll");
    HMODULE plugin = state->optiSlDLSSG != nullptr ? state->optiSlDLSSG : GetModuleHandleW(L"sl.dlss_g.dll");
    if (snippet == nullptr && plugin == nullptr)
        return; // DLSSG modules not loaded yet; the per-frame EnsureApplied retries

    // Each module is patched independently and only once, so Apply() may be called
    // at several points (LoadStreamline, InitWithD3D12, per frame) and simply
    // applies whichever module is present but not yet patched. Ordering matters:
    // nvngx_dlssg.dll is mapped before slInit builds the NGX feature, and the
    // arch-gate result (MultiFrameCountMax / m_multiFrameSupported) is evaluated
    // while that feature is created -- so the snippet has to be patched BEFORE
    // slInit, while the plugin (sl.dlss_g.dll) is only available after it.
    if (snippet != nullptr && !g_snippetPatched)
    {
        g_snippetPatched = true;
        // The arch gate is the actual enable; the midpoint fix is quality. Track
        // the gate separately so g_applied reflects whether MFG is usable.
        g_archGatesOk = PatchNgxArchGates(snippet);
        g_temporalOk = PatchNgxMidpoint(snippet);
        if (g_archGatesOk)
        {
            g_applied.store(true, std::memory_order_release);
            // Arch gate just raised the advertised max; let the caller re-read
            // numFramesToGenerateMax so the MFG count selector appears.
            g_justApplied.store(true, std::memory_order_release);
            LOG_INFO("MfgUnlock: arch gates landed in nvngx_dlssg.dll; MFG cap raised to 5 (temporal {})",
                     g_temporalOk ? "patched" : "skipped");
        }
    }

    if (plugin != nullptr && !g_pluginPatched)
    {
        g_pluginPatched = true;
        g_flipMeterOk = PatchSlFlipMetering(plugin); // pacing is critical for 3x+; logs its outcome
        g_ceilingOk = PatchSlFrameCeiling(plugin);
        g_drsClampOk = PatchSlDrsClamp(plugin);
    }
}

void EnsureApplied()
{
    Apply();
}

void Restore()
{
    RestorePointerPatches();
    RestoreCodePatches();
    g_snippetPatched = false;
    g_pluginPatched = false;
    g_archGatesOk = false;
    g_temporalOk = false;
    g_flipMeterOk = false;
    g_ceilingOk = false;
    g_drsClampOk = false;
    g_applied.store(false, std::memory_order_release);
    g_justApplied.store(false, std::memory_order_release);
}

bool IsApplied()
{
    return g_applied.load(std::memory_order_acquire);
}

bool ConsumeJustApplied()
{
    return g_justApplied.exchange(false, std::memory_order_acq_rel);
}

Status GetStatus()
{
    Status s;
    s.enabled = MfgUnlockEnabled();
    s.archGates = g_archGatesOk;
    s.temporal = g_temporalOk;
    s.flipMeter = g_flipMeterOk;
    s.ceiling = g_ceilingOk;
    s.drsClamp = g_drsClampOk;
    s.maxGenerated = g_archGatesOk ? 5 : 1;
    return s;
}

} // namespace MfgUnlock
