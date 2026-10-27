# KSU：核心模組與管理器產物

這個目錄是 Root My Zenfone 的 KernelSU 整合產物：三份 patch、一個核心模組 `.ko`、一個官方管理器 APK、兩個 per-boot 重定位工具與它們的自我測試（`tools/`）。要重建模組，另需 kernel source tree、編譯器與簽章私鑰。

整合的原理與失敗模式見 [`../docs/04-resukisu.md`](../docs/04-resukisu.md)；ELF 層級的三項載入條件見 [`../docs/04-resukisu.md`](../docs/04-resukisu.md) §1。

---

## 1. 目錄內容

| 路徑 | 大小 | 內容 |
|---|---:|---|
| `patch/0001-zf8-device.patch` | 17626 bytes | 對 BakaSU／ReSukiSU 的 device delta；產生時的 base 是 `487b32da`（`v4.2.0-rc2-12`） |
| `patch/0002-zf8-tag-build.patch` | 996 bytes | release tag 專屬：`init.c` 的 late-load permissive 分支、CFI stub |
| `artifacts/kernelsu-zf8-rc3-officialkey.ko` | 336336 bytes（已 strip debug section） | 以 `v4.2.0-rc3` 為基礎、套上述 patch 的 LKM（隨附 binary 另經字串清理）；三項 ABI 條件通過，但仍有 193 個 UNDEF，載入前必須做 per-boot 重定位 |
| `tools/ko_absinfix.py` | 3825 bytes | 把 `SHN_UNDEF` 的 symbol 改寫成 `SHN_ABS` + runtime 位址 |
| `tools/ko_loadable.py` | 7538 bytes | 一次做完套 delta、重定位、`__versions` 歸零與四項檢查（§2.5） |
| `tools/test_reloc.py` | 4395 bytes | 用假 kallsyms 驗證重定位只動應該動的欄位 |
| `patch/0003.files.sha256` | 1,094 bytes | 0003 的 12 個 pre-image 的 SHA-256，套用前用它驗 base |
| `config/zf8-module.config` | 185,843 bytes | 建置用的 kernel config；`STACKPROTECTOR=y`、`STACKPROTECTOR_PER_TASK` 未設 |
| `build.sh` | — | 從 kernel source drop 與本目錄的 patch 端到端重建 `.ko` |

`0001` 的主要內容：

- `kernel/Kbuild`：加入 `CONFIG_KSU_ZF8_LATE_LOAD`、`CONFIG_KSU_NO_OBSERVER`、`CONFIG_KSU_NO_SELINUX_HIDE`、`CONFIG_KSU_NO_TABLE_PATCH`，以及 CFI stub（`cfi_stub.o`，排在最後）的 build 規則。
- `kernel/core/init.c`：late-load 分支的初始化順序、跳過 `selinux_hide`、保留 SELinux permissive。
- `kernel/hook/syscall_hook_manager.c`：`sys_enter` tracepoint 的 reboot magic、zygote→manager 的 fd 安裝、manager 的 seccomp 抑制。
- `kernel/supercall/supercall.c`：非 CLOEXEC 的 fd 安裝變體。
- `kernel/manager/pkg_observer.c`：5.4 的 fsnotify callback 簽名與 `CONFIG_KSU_NO_OBSERVER` 跳過路徑。
- `kernel/runtime/ksud_integration.c`：kprobe 路徑的 `CONFIG_KPROBES` 條件編譯。
- `manager/.../KernelRepository.kt`：移除 `isGKI()` 閘，讓 5.4 也能回報 LKM 模式。

`0003` 套在 kernel 樹上，動 12 個檔：三個決定 ABI（`module.h`、`cfi.h`、`modpost.c`），八個是 GCC 相容修正。

`0002` 只有兩個 hunk：建立 `kernel/cfi_stub.c`（含 alignment pad，讓 `__cfi_check` 不落在頁邊界），以及在 `kernel/core/init.c` 的 `kernelsu_init()` 裡，把 `setenforce(true)` 包進 `CONFIG_KSU_ZF8_LATE_LOAD` 分支，late-load 時保持 permissive。

**不在這個目錄的東西**：kernel source tree、cross compiler、manager 簽章私鑰。

---

## 2. 從原始碼建置模組

### 2.1 前置條件

- Linux x86_64 host，`aarch64-linux-gnu-gcc-12`、`aarch64-linux-gnu-binutils`、Python 3。
- ASUS Zenfone 8 的 `33.0210.0210.296` source drop（`5.4.147`）。裝置跑的是 `.337`／`5.4.210-qgki-perf-g6e91db764350`，ASUS 沒有為那個 build 公布 source drop，所以 base 是 `.296`。**不能隨意換樹**：與裝置不同的 build tree 可能產生 896 bytes 的 `struct module`（結構定義不同的 build tree 產生的模組即是），這台裝置是 960 bytes，載入會失敗。
- **裝置 config 與 module 的 build config 是兩份不同的 config。** 逐項差異見 [`../docs/04-resukisu.md`](../docs/04-resukisu.md) §2.2；module 沒有 `CONFIG_CFI_CLANG`（它依賴 `LTO_CLANG`）。
- **GCC build 需要 kernel 側的佈局編輯，這些在 `patch/0003-zf8-kernel-side.patch` 內。** `include/linux/module.h` 的 `cfi_check`／`jump_entries`／`num_jump_entries` 改成無條件存在、`include/linux/cfi.h` 的 `cfi_check_fn` 與 `__cfi_check` 宣告改成無條件存在、`scripts/mod/modpost` 在 `.mod.c` 多吐 `.cfi_check = __cfi_check`；逐項說明見 [`../docs/04-resukisu.md`](../docs/04-resukisu.md) §2.2。驗收用 `tools/ko_loadable.py verify`：`this_module.sh_size == 0x3c0` 加上三個 relocation offset。只驗 size 不夠——`struct module` 是 cacheline 對齊，缺 `cfi_check` 也照樣進位成 960。module 的 `__cfi_check` 是 `0002` 的 `kernel/cfi_stub.c` 提供的空 stub，不是 CFI instrumentation。
- BakaSU source，tag `v4.2.0-rc3`（commit `239e1e8871b8fcd51a6e5b3002e0ba522fdd99fb`）。
- 完整 git clone。`kernel/Kbuild` 會用 `git rev-list --count HEAD` 算版本；沒有 `.git` 會直接報錯。下面另外用 `KSU_VERSION` 覆寫成 35171，但 clone 仍必須有歷史。

### 2.2 取得 source 並套 patch

```sh
git clone https://github.com/Baka-SU/BakaSU.git
cd BakaSU
git checkout v4.2.0-rc3

PUB=/path/to/repo/ksu
git apply "$PUB/patch/0001-zf8-device.patch"
```

`0001` 是對 `487b32da` 產生的，套在 release tag 上時全部 hunk 乾淨套用。接著套 `0002`：

```sh
git apply "$PUB/patch/0002-zf8-tag-build.patch"
```

`0002` 建立 `kernel/cfi_stub.c`，並在 `init.c` 加上 late-load 的 permissive 分支。`cfi_stub.o` 的 build 規則在 `0001` 的 `Kbuild` hunk 裡，所以順序不能顛倒。完成後不需要手動編輯任何 C 檔。

接著處理 kernel 樹。`0003` 不是套在 ReSukiSU 上，是套在 ASUS source drop 上。先驗 base：

```sh
KDIR=/path/to/zenfone8_zs672ks.mp-33.0210.0210.296/kernel/msm-5.4
cd "$KDIR"
sha256sum -c "$PUB/patch/0003.files.sha256"
```

12 個檔全部 `OK` 才繼續。`git apply` 不看 patch 的 `index` 行，所以這一步不能省。然後套用：

```sh
git apply "$PUB/patch/0003-zf8-kernel-side.patch"   # 樹是 git repo 時
patch -p1 < "$PUB/patch/0003-zf8-kernel-side.patch" # 不是的時候
```

套完的樹就是 §2.3 的 `KDIR`。少這一步，`struct module` 會少 `cfi_check`，`modpost` 也不會吐 `.cfi_check`。

### 2.3 編譯

```sh
KDIR=/path/to/5.4.210-kbuild-tree
make -C "$KDIR" M="$PWD/kernel" ARCH=arm64 \
  CROSS_COMPILE=aarch64-linux-gnu- CC=aarch64-linux-gnu-gcc-12 \
  KBUILD_MODPOST_WARN=1 DISABLE_WRAPPER=1 \
  CONFIG_KSU=m CONFIG_KSU_TRACEPOINT_HOOK=y CONFIG_KSU_MULTI_MANAGER_SUPPORT=y \
  KSU_EXPECTED_SIZE=0x377 \
  KSU_EXPECTED_HASH=d3469712b6214462764a1d8d3e5cbe1d6819a0b629791b9f4101867821f1df64 \
  KSU_VERSION=35171 modules -j4
```

| 參數 | 作用 |
|---|---|
| `KBUILD_MODPOST_WARN=1` | 模組引用了一批沒有 export 的核心符號（193 個）；modpost 只警告，不中斷建置 |
| `CONFIG_KSU=m` | 以外部模組建置；`#ifdef MODULE` 會讓 GET_INFO 回報 `KSU_GET_INFO_FLAG_LKM`（`kernel/supercall/dispatch.c:67-69`） |
| `CONFIG_KSU_TRACEPOINT_HOOK=y` | 用 tracepoint 攔 syscall；patch 另外定義 `CONFIG_KSU_NO_TABLE_PATCH`，不改 `sys_call_table` |
| `CONFIG_KSU_MULTI_MANAGER_SUPPORT=y` | 啟用多管理器簽章表；`KSU_EXPECTED_*` 的 custom 條目在這個 ifdef 內（`kernel/manager/apk_sign.c:34-49`） |
| `KSU_EXPECTED_SIZE` | 管理器簽章憑證的 DER 長度，`0x377` = 887 bytes。Kbuild 把它編成 `EXPECTED_SIZE`（`kernel/Kbuild:222-229`） |
| `KSU_EXPECTED_HASH` | 同一張憑證的 SHA-256。長度與雜湊要成對；只對一個，管理器不會被 crown |
| `KSU_VERSION` | 回報給管理器的版本號。官方 APK 的 versionCode 是 35171，本專案讓兩者一致；這個值不參與 UAPI 相容判斷 |
| `DISABLE_WRAPPER=1` | 必須。這棵樹的 `Makefile:430` 會把 `CC` 換成 `scripts/gcc-wrapper.py`，它把編譯錯誤印成 `b'...'` 並讓 `modules_prepare` 失敗 |

`CC` 要釘死 `aarch64-linux-gnu-gcc-12`：`olddefconfig` 會把實際的編譯器寫進 `CONFIG_CC_VERSION_TEXT`／`CONFIG_GCC_VERSION`，換版本建出來的 `.text` 不同。

建置前 tree 裡不能有 `vmlinux`。`scripts/Makefile.modpost` 會把 `$(wildcard vmlinux)` 交給 modpost，modpost 從它的 `__crc_*` 撈出 CRC，`__versions` 就變成 9,216 bytes。把 `vmlinux` 移走、`Module.symvers` 清空，`__versions` 自然是 0，§2.4 的手動改寫就不需要了。

產物是 `kernel/kernelsu.ko`。

### 2.4 把 `__versions` 的 `sh_size` 寫成 0

build tree 會把自身的 CRC 寫進 `__versions`；這台裝置的 kernel 不一定接受。目標狀態是「section 存在、0 entries」：核心仍走有 CRC 的 vermagic 尾段比對，但 CRC 迴圈不執行（`kernel/module.c:1278-1325`、`:1345-1353`；行號以上游 stable v5.4.210 為準，摘要見 `../docs/04-resukisu.md` §1.2）。

```sh
mkdir -p dist
python3 - kernel/kernelsu.ko dist/kernelsu.ko <<'PY'
import struct, sys
src, dst = sys.argv[1], sys.argv[2]
d = bytearray(open(src, "rb").read())
shoff, = struct.unpack_from("<Q", d, 0x28)
shentsize, shnum, shstrndx = struct.unpack_from("<HHH", d, 0x3A)
stroff, = struct.unpack_from("<Q", d, shoff + shstrndx * shentsize + 0x18)
for i in range(shnum):
    o = shoff + i * shentsize
    nameoff, = struct.unpack_from("<I", d, o)
    end = d.index(b"\0", stroff + nameoff)
    if d[stroff + nameoff:end] == b"__versions":
        struct.pack_into("<Q", d, o + 0x20, 0)   # sh_size
        break
else:
    sys.exit("no __versions section")
open(dst, "wb").write(d)
print("wrote", dst)
PY
```

不要用 `objcopy --remove-section=__versions` 取代這一步：section 不存在時，核心走的是 `try_to_force_load()` 那條路，而不是「0 entries」的放行路徑（`kernel/module.c:1294-1296`）。

### 2.5 Per-boot 的 UNDEF 重定位

到 §3 的三項檢查為止，產物只通過 ELF 層級的閘。它仍有 193 個 UNDEF；載入前必須把每個 UNDEF 的 `st_shndx` 改成 `SHN_ABS`、`st_value` 改成**本次開機**的 `/proc/kallsyms` 位址。KASLR 讓每次開機的位址不同，重開機後要重新產生 `out.ko`，不能沿用上一次的檔案。

做法與判據見 `../docs/04-resukisu.md` §1.4 與 §2.5；兩個工具就在 [`tools/`](tools/)，自我測試是 `tools/test_reloc.py`：

```sh
# in.ko 是 §2.4 之後的檔案；link_kallsyms 取自建置樹（nm vmlinux 或 System.map），
# delta = 該次開機 PoC log 的 runtime _text - link_kallsyms 第一行的 link-time _text
python3 tools/ko_loadable.py build in.ko link_kallsyms.txt 0x1590e00000 out.ko
python3 tools/ko_loadable.py verify out.ko
# 期望：四項全 ✓（三項 ABI 條件 + UNDEF 全部已重定位）
```

`tools/ko_absinfix.py` 只做重定位（改寫每個 UNDEF 的 `st_shndx`／`st_value`），`tools/ko_loadable.py` 依序做套 delta、呼叫前者、把 `__versions` 的 `sh_size` 寫成 0、再驗四項。三項通過但沒有做重定位，`insmod` 仍會因未解析的符號失敗。

---

## 3. 確認產物可載入

### 3.1 三項 ABI 檢查

| # | 檢查 | 通過值 | 不通過的後果 |
|---|---|---|---|
| 1 | `.gnu.linkonce.this_module` 的 `sh_size` = `sizeof(struct module)` | `0x3c0` = 960 | 佈局錯誤的模組（例如 896 bytes）會在 `post_relocation()` 的 `sort_extable()` 踩壞資料，oops 發生在 vermagic 檢查之後；`panic_on_oops=1` 時直接重開機 |
| 2 | `__versions` 的 `sh_size` | `0`（section 存在、0 entries） | 非 0 時 CRC 不符，`insmod` 回 `Exec format error`；section 不存在時走 force-load 路徑 |
| 3 | `vermagic` | `5.4.210-qgki-perf-g6e91db764350 SMP preempt mod_unload modversions aarch64` | 核心回 `version magic ... should be ...`，載入失敗 |

可以直接用這一段斷言：

```sh
set -e
test "$(aarch64-linux-gnu-objdump -h dist/kernelsu.ko | awk '$2==".gnu.linkonce.this_module"{print $3}')" = 000003c0
test "$(aarch64-linux-gnu-objdump -h dist/kernelsu.ko | awk '$2=="__versions"{print $3}')" = 00000000
test "$(modinfo -F vermagic dist/kernelsu.ko)" = \
  '5.4.210-qgki-perf-g6e91db764350 SMP preempt mod_unload modversions aarch64'
echo "three gates pass"
```

沒有 `modinfo` 時，第三項可以用 `readelf -p .modinfo dist/kernelsu.ko | grep vermagic` 讀。

第三項刻意比對完整字串。核心的實際規則是：`__versions` 存在時（第二項成立的狀態），`same_magic()` 只比第一個空格之後的尾段，版本前綴不參與（`kernel/module.c:1345-1353`）；`__versions` 不存在時才比完整字串。完整字串比對因此比核心更嚴格，也與隨附 artifact 一致。

第三項的 vermagic 版本前綴來自 build tree 的 `include/generated/utsrelease.h`（`UTS_RELEASE`），不是 `Makefile` 的 `VERSION`／`PATCHLEVEL`／`SUBLEVEL`，也不是 `make -s kernelrelease` 的輸出。`make -s kernelrelease` 依 `Makefile` 與 `.config` 的 `CONFIG_LOCALVERSION` 算出 `5.4.147-qgki-perf`；實際編進 module 的是 `utsrelease.h` 的 `5.4.210-qgki-perf-g6e91db764350`。external module 建置（`make -C "$KDIR" M=... modules`）不會重新產生這個檔；對同一棵樹做完整的 in-tree 建置或 `mrproper` 後重建，`utsrelease.h` 會被 `Makefile` 的版本覆寫成 `5.4.147-qgki-perf`，第三項就失敗。建置前先確認：

```sh
grep UTS_RELEASE "$KDIR/include/generated/utsrelease.h"
# 期望：#define UTS_RELEASE "5.4.210-qgki-perf-g6e91db764350"
```

這個字串要和裝置的 vermagic 前綴一致；不一致時，先修正 build tree 的版本欄位與 `CONFIG_LOCALVERSION`（`LOCALVERSION_AUTO` 會再附加 git describe 的尾碼），再編譯。

### 3.2 選用但有用的錨點

```sh
readelf -r dist/kernelsu.ko | grep -E 'init_module|cleanup_module|__cfi_check'
# 期望：0x108 __cfi_check、0x188 init_module、0x378 cleanup_module
```

這三個 relocation offset 與隨附的 `.ko` 相同（實測），可以用來確認 CFI stub 與 init／exit 的佈局沒有跑掉。

### 3.3 UNDEF 與載入

```sh
aarch64-linux-gnu-nm -u dist/kernelsu.ko | wc -l
# 重定位前：193
# 重定位後：0
```

載入後以 `/proc/modules` 實查，不要只看 `insmod` 的 stderr：

```sh
insmod /data/local/tmp/ksu.ko allow_shell=1
grep '^kernelsu ' /proc/modules
# 期望：kernelsu <size> 0 - Live ...

# 從 exploit 的 root server 直接跑 ksud 會回全 0：它沒有 KSU 的驅動 fd。
# 開一次管理器，再看 dmesg：
dmesg | grep "install ksu fd" | tail -3
# 期望：KernelSU: [<pid>] install ksu fd: N
```

`allow_shell=1` 只建議在 bring-up 時使用；它讓 UID 2000 可以呼叫 `GRANT_ROOT`。`ksud debug info` 會印出 `version`、`flags`、`uapi_version`、`features`、`lkm` 等欄位（`userspace/ksud/src/android/cli.rs:792-809`）。

---

## 4. 與管理器配對

### 4.1 使用官方 APK

管理器從上游 release 取得：
<https://github.com/Baka-SU/BakaSU/releases/tag/v4.2.0-rc3> 的
`ReSukiSU_v4.2.0-rc3_35171-arm64-v8a-release.apk`。它的簽章憑證是模組信任的那一張：

```sh
apksigner verify --print-certs ReSukiSU_v4.2.0-rc3_35171-arm64-v8a-release.apk
# Signer #1 certificate DN: CN=ReSukiSU, OU=N/A, O=ReSukiSU, L=Shantou, ST=Guangdong, C=CN
# Signer #1 certificate SHA-256 digest: d3469712b6214462764a1d8d3e5cbe1d6819a0b629791b9f4101867821f1df64
```

APK 的第一個 v2 certificate DER 是 887 bytes（`0x377`），SHA-256 與上表一致。APK 的 package 是 `com.resukisu.resukisu`，versionCode 35171，versionName `v4.2.0-rc3`。

### 4.2 模組的配對值

建置時使用：

```
KSU_EXPECTED_SIZE=0x377
KSU_EXPECTED_HASH=d3469712b6214462764a1d8d3e5cbe1d6819a0b629791b9f4101867821f1df64
KSU_VERSION=35171
```

`KSU_EXPECTED_*` 是管理器 APK 的簽名憑證，不是 APK 大小。`KSU_VERSION` 對齊 APK 的 versionCode；UAPI 則是另一個契約，兩邊都必須是 4。

管理器端的 UAPI 是編在 `libkernelsu.so` 的常數；對官方 APK 反組譯，`getManagerUAPIVersion` 是 `mov w0, #0x4; ret`：

```sh
unzip -p ReSukiSU_v4.2.0-rc3_35171-arm64-v8a-release.apk lib/arm64-v8a/libkernelsu.so > /tmp/libkernelsu.so
aarch64-linux-gnu-objdump -d /tmp/libkernelsu.so | grep -A2 getManagerUAPIVersion
```

模組端的 UAPI 是 tag 的 `uapi/supercall.h:20`：`static const __u32 KERNEL_SU_UAPI_VERSION = 4;`。

### 4.3 安裝與 crowning 順序

1. 先安裝 manager APK。
2. 重開機，重跑 exploit 鏈，載入模組。
3. 模組 init 時掃描 `/data/app`，用憑證把 manager 的 UID 註冊成 manager。
4. 驗證：

```sh
ksud debug get-sign /data/app/.../base.apk
# 期望：size: 0x377, hash: d3469712...

ksud module list
# 成功代表 manager 已被 crown；Permission denied 代表尚未 crown
```

這個 patch 關掉了 package observer（`CONFIG_KSU_NO_OBSERVER`），所以模組載入後才安裝／更換 APK 不會自動重新 crowning。若在模組載入後才換 APK，必須重開機、重跑鏈、重新 `insmod`。

### 4.4 症狀對照

| 症狀 | 原因 | 處理 |
|---|---|---|
| `Manager update required` | kernel UAPI > manager UAPI | 把 manager 換成與模組同 UAPI 的版本；不要裝 CI build |
| `Kernel update required` | manager UAPI > kernel UAPI | 把模組換成與 manager 同 UAPI 的版本 |
| `ksud module list` → `Permission denied` | manager 未被 crown | 確認 APK 已安裝、憑證正確，重開機後重跑鏈與 `insmod` |
| 首頁 `Unsupported` | `isManager=false`（未 crown，或 kernel 沒有管理器） | 先解決 crowning |
| `The manager you are using is not the official ... manager` | APK 不是官方簽名（自建 debug 簽章） | 換官方 APK；kernel 可能仍信任自訂憑證，但這個警告不會消失 |

**不要安裝「新測試版 35233」**：那是 GitHub Actions 的 CI build，UAPI 是 5；安裝後會出現 `Manager update required`，直到模組也從 HEAD 重建。

---

## 5. 產物出處

| 產物 | 大小 | MD5 | SHA-256 |
|---|---:|---|---|
| `patch/0001-zf8-device.patch` | 17626 | `2d2e8fd48b90bd208f363c4c47bb2777` | `929dac06d9d231c78778119ffc5538450a09f7a3946b1ede3200b85ff9697f33` |
| `patch/0002-zf8-tag-build.patch` | 996 | `4ea24de75db43b458149df1e3a56bd6a` | `3a365636af122bc79a83dc8762771c44427e3ede52cf63edff87e0ec3cfe3f97` |
| `patch/0003-zf8-kernel-side.patch` | 7331 | `82e1807ec3d929a73caa64ac76106516` | `d9c18e386e3572bc3b100774b043438319e2b8229974a3a9908e89d3f6445513` |
| `artifacts/kernelsu-zf8-rc3-officialkey.ko` | 336336 | `2c1864e9655ae04b2f7bd9b36fbb6b25` | `58527943b35418eb8575ce029b95a7f719eaec3a4a5220968aaa9a2178e87b91` |

**模組。** 版本字串 `v4.2.0-rc3-239e1e88-dirty@ReSukiSU`，內嵌 `KSU_VERSION` = `0x8963` = 35171（`do_get_info` 反組譯實測）。上游 tag `v4.2.0-rc3` 的 commit 是 `239e1e8871b8fcd51a6e5b3002e0ba522fdd99fb`；`35171` 的來源是 Kbuild 的公式 `30000 + rev-list-count + 700`，這個 tag 的 `git rev-list --count HEAD` 是 4471（實測）。`-dirty` 表示建置樹有未提交的 patch。

**管理器。** 取自 `https://github.com/Baka-SU/BakaSU/releases/tag/v4.2.0-rc3` 的 arm64 asset，與本目錄副本位元相同（`cmp` 無差異，實測）。

**簽章憑證。** Subject `CN=ReSukiSU, OU=N/A, O=ReSukiSU, L=Shantou, ST=Guangdong, C=CN`；DER 887 bytes（`0x377`）；SHA-256 `d3469712b6214462764a1d8d3e5cbe1d6819a0b629791b9f4101867821f1df64`；SHA-1 `03351e274c23c969f96b46d6be715c1ebedd5f9c`；MD5 `b829cfbbb3043c4f0609f113422d0d77`。前兩項是核心比對用的值，SHA-1／MD5 只用來對照其他工具的輸出。

**重建的限制。** 本目錄不含 build tree；三份 patch 是可重現的輸入，patch 以外的建置狀態（toolchain 版本、目錄路徑）不是。重建的 md5 不保證相同：建置會把 debug info 與建置路徑寫進 `.ko`，換一個目錄重建，大小與 md5 都會變。三項 ABI 條件、this_module relocation 與 UNDEF 的形狀（193 個）才是要比對的。隨附的 `.ko` 是三個輸入共同的產物：上游 `v4.2.0-rc3`、`patch/0001`＋`patch/0002`，以及 kernel 側的三項佈局編輯（`include/linux/module.h`、`include/linux/cfi.h`、`scripts/mod/modpost`；見 §2.1 與 [`../docs/04-resukisu.md`](../docs/04-resukisu.md) §2.2）。`sh_size` 歸零不移除 section 內容，重建檔會比隨附檔大約 9 KB。2026-10-20 從 tag 重新套 `0001`／`0002` 並完成那三項編輯後建置，`rc=0`，三項閘門全數通過。

---

## 6. 已知顯示問題

### 6.1 首頁顯示 Built-in 而不是 LKM

官方 APK 的 `KernelRepository` 仍把 `lkmMode` 的讀取放在 `isGKI()` 之後（`KernelRepository.kt:34`）；`isGKI()` 在 5.4 回 false（`Kernels.kt:12-16`），所以 `lkmMode` 是 null，UI 落到 `HomePage.kt:561-563` 的 `else -> "Built-in"`。kernel 側的 `GET_INFO` 其實有設 `KSU_GET_INFO_FLAG_LKM`（`dispatch.c:67-69`），所以 `ksud debug info` 會顯示 `lkm: true`。

這是 manager 的顯示 bug，不是 kernel 回報錯誤。`0001` 對 `KernelRepository.kt` 有對應的一行修正；官方 APK 沒有套用。自行建置 manager APK 可以修掉，但自簽 APK 會出現下一節的警告。

### 6.2 CI build 的 UAPI 不匹配

管理器的更新檢查會讀 GitHub Actions 的 CI build，不只讀正式 release。CI build（如 35233）的 UAPI 可能高於 release 的 4；安裝後 manager 與模組的 UAPI 不匹配。忽略這個提示，或把更新檢查關掉。

### 6.3 自簽 manager 的「非官方管理器」警告

APK 的 `isOfficialSignature` 會把 `ksud debug get-sign` 的結果與硬編碼的官方憑證比對（`KsuCli.kt:167`）。自行用 debug keystore 簽的 APK 會得到不同的 `(size, hash)`，首頁因此顯示 `The manager you are using is not the official ... manager, and you may not be able to obtain permissions.`。kernel 可以透過 `KSU_EXPECTED_*` 信任這張憑證，crowning 與功能仍可用；這個警告只是顯示層的提醒。要消除它，只能使用官方簽名的 APK。
