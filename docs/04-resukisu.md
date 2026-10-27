# ReSukiSU／BakaSU 核心模組整合

核心模組把 root 從使用者空間行程移到 kernel 內的授權端點。整合要對齊四件事：模組與 kernel 的 ELF ABI、模組與管理器的 UAPI 與簽名憑證、supercall（透過 `reboot(2)` magic 取得 KSU driver fd 再以 ioctl 下命令）的 fd 與權限檢查、每次開機的符號重定位。`ksu/` 的產物與上游 `v4.2.0-rc3` 原始碼是下列數字的基準。

---

## 1. 三項 ABI 條件

模組是 ELF object，載入一個已跑了一段時間的 kernel。載入器檢查三件事；條件二、三不滿足時 `insmod` 回 `-ENOEXEC`，busybox 顯示 `Exec format error`；條件一不滿足時不會回 `-ENOEXEC`：relocation 錯位會 oops（`panic_on_oops=1` 下重開機），或留下 `Live` 但 `init` 從未被呼叫的模組。

| # | 條件 | 通過值 | 不滿足時 |
|---|---|---|---|
| ① | `.gnu.linkonce.this_module` 的 `sh_size` = `sizeof(struct module)` | `0x3c0` = 960 bytes | relocation 落在錯誤欄位；`sort_extable()` oops，`panic_on_oops=1` 下變成重開機；或 `Live` 但 `init` 從未被呼叫 |
| ② | `__versions` section 存在，`sh_size` = 0 | `000000` | 非零：CRC 不符；`module_layout` 回 `-ENOEXEC`，其他符號在 `simplify_symbols()` 回 `-EINVAL`；不存在：`try_to_force_load()` 失敗，`-ENOEXEC` |
| ③ | vermagic 與裝置相同 | `5.4.210-qgki-perf-g6e91db764350 SMP preempt mod_unload modversions aarch64` | `check_modinfo()` 回 `-ENOEXEC`，kmsg 印 `version magic '...' should be '...'` |

### 1.1 條件一：`sizeof(struct module)` = 960

這台裝置的 `sizeof(struct module)` 是 `0x3c0` = 960 bytes，一般 5.4 樹是 896。多出的 64 bytes 來自佈局差異：build tree 把 `cfi_check` 與 `jump_entries`／`num_jump_entries` 改成無條件存在（§2.2）；`source_list`／`target_list` 在兩棵樹都有（`CONFIG_MODULE_UNLOAD=y`），不是差異來源。`[推論]`

載入器把模組的 `this_module` blob 複製到 kernel 的 `struct module`，再套用模組自己的 relocation。896-byte 佈局的 `init`／`exit` relocation offset 與真機的 960-byte 佈局不同：`init` 的 RELA 會寫到真機的 `num_exentries` 附近，`post_relocation()` 的 `sort_extable()` 用被污染的數量走訪 extable，於是在 `cmp_ex_sort ← sort_extable ← load_module` 路徑上 oops，`CONFIG_PANIC_ON_OOPS=y` 把它放大成重開機。若被污染的欄位沒踩到 extable 計數，模組會出現在 `/proc/modules` 的 `Live` 清單但 `init` 從未被呼叫、supercall 也不回應——Live-but-dead 與 oops 是同一種 ABI 錯位的不同表現。`[推論，基於 relocation 佈局]`

```sh
readelf -SW kernelsu.ko | grep this_module
# 期望：... .gnu.linkonce.this_module PROGBITS ... 0003c0 ...
```

### 1.2 條件二：`__versions` 存在，`sh_size` = 0

5.4 的 `kernel/module.c` 對兩種情況處理不同：section 不存在（`info->index.vers == 0`）時 `check_version()` 呼叫 `try_to_force_load()`，`CONFIG_MODULE_FORCE_LOAD` 未設回 `-ENOEXEC`；section 存在但 `sh_size = 0` 時 `num_versions = 0`，CRC 迴圈不執行，函式印一次 `no symbol version for module_layout` 後回傳 1。

`same_magic()` 的 `has_crcs` 是 `info->index.vers`（section 是否存在），不是 `sh_size`。因此「存在但 0 entries」讓 vermagic 只比對第一個空格之後的尾段；section 不存在時才比對完整字串（stable v5.4.210 `kernel/module.c:1345-1353`、`:3276`）。非零的失敗模式是 `__versions` 裡帶著別棵 build tree 算出的 CRC：`module_layout` 的 CRC 不符會讓呼叫端在 `layout_and_allocate()` 之前以 `-ENOEXEC` 結束；其他符號的 CRC 不符在 `simplify_symbols()` 回 `-EINVAL`。`objcopy --remove-section=__versions` 會成功（rc=0）並把 section 與 `____versions` 符號一起移除，結果是 section 不存在，走 `try_to_force_load()` 的失敗路徑。

```sh
readelf -SW kernelsu.ko | grep __versions
# 期望：... __versions PROGBITS ... 000000 ...
```

### 1.3 條件三：vermagic

```
5.4.210-qgki-perf-g6e91db764350 SMP preempt mod_unload modversions aarch64
```

條件二成立時 `same_magic()` 只比對第一個空格之後的尾段 `SMP preempt mod_unload modversions aarch64`，版本前綴不參與；這是 5.4.147 樹編出的模組可能通過 vermagic、卻在其他條件失敗的原因。尾段缺 `modversions`（build tree 沒開 `CONFIG_MODVERSIONS`）或 `SMP`／`PREEMPT` 不同，`check_modinfo()` 直接回 `-ENOEXEC`。不含 `modversions ` 的字串是 62 字元，加上後 74 字元；不能原地覆寫，必須在編譯期產生正確字串。檢查用 `modinfo -F vermagic kernelsu.ko`。

### 1.4 三項之外：UNDEF 重定位

模組 late-load 到已跑一段時間的 kernel，引用的符號多數不是裝置的 exported symbol。build 時用 `KBUILD_MODPOST_WARN=1` 讓 modpost 只警告，產物因此帶著 UNDEF；載入時 `simplify_symbols()` 逐一解析，找不到就 `-ENOENT`（`Unknown symbol`）。

隨附 artifact `ksu/artifacts/kernelsu-zf8-rc3-officialkey.ko` 有 193 個 UNDEF（`aarch64-linux-gnu-nm -u | wc -l`）。三項 ABI 條件全過，但這些 UNDEF 要在載入前改寫成 `SHN_ABS` + 本次開機的 runtime 位址（§2.5），不是可直接 `insmod` 的最終產物。

---

## 2. 模組建置

### 2.1 上游 tag 與 device patch

上游是 BakaSU（原 ReSukiSU），`https://github.com/Baka-SU/BakaSU`；舊的 `ReSukiSU/ReSukiSU` URL 會 redirect。release tag `v4.2.0-rc3`，commit `239e1e8871b8fcd51a6e5b3002e0ba522fdd99fb`。模組內嵌版本字串 `v4.2.0-rc3-239e1e88-dirty@ReSukiSU`；`-dirty` 表示 build tree 有未提交的 device patch。

`ksu/patch/` 有三份 patch。`0001`、`0002` 套在 ReSukiSU 上，`0003` 套在 kernel 樹上：

- `0001-zf8-device.patch`（17,626 bytes）：device delta，base 是 `487b32da`（`v4.2.0-rc2-12-g487b32da8`）。在 rc3 上全部 hunk 乾淨套用。
- `0002-zf8-tag-build.patch`（996 bytes）：tag 移植層：建立 `kernel/cfi_stub.c`，並在 `init.c` 加上 late-load 的 permissive 分支。
- `0003-zf8-kernel-side.patch`（7,331 bytes）：kernel 樹的 ABI 與 GCC 相容修正，12 個檔，詳見 §2.2。

`0002` 補上的 hunk 保留 late-load 模式的 permissive 狀態，不執行 `setenforce(true)`。`kernel/cfi_stub.c` 是 module-side 的 CFI landing pad，link 在最後，讓 `__cfi_check` 不是 page-aligned；artifact 只有一個 `__cfi_check` relocation，位於 `this_module` 的 `0x108`（`readelf -r`）。

`0001` 的內容：Kbuild 加 `CONFIG_KSU_ZF8_LATE_LOAD`、`CONFIG_KSU_NO_OBSERVER`、`CONFIG_KSU_NO_SELINUX_HIDE`、`CONFIG_KSU_NO_TABLE_PATCH` 四個開關與 `cfi_stub.o`；`init.c` 在 late-load 分支跳過 `selinux_hide`；`syscall_hook_manager.c` 在 `sys_enter` tracepoint 內聯處理 reboot magic、zygote→manager 的 fd 安裝與 manager 的 seccomp 抑制；`supercall.c` 新增非 CLOEXEC 的 fd 安裝變體；`pkg_observer.c` 加 5.4 的 fsnotify callback 簽名與 `CONFIG_KSU_NO_OBSERVER` 跳過路徑；`ksud_integration.c` 把 kprobe 路徑用 `CONFIG_KPROBES` 包起來；`KernelRepository.kt` 移除 `isGKI()` 閘。

### 2.2 Build tree 與工具鏈

`struct module` 的大小、欄位偏移、vermagic 都是 build tree 的屬性；不是這個 build tree 的佈局會在條件一失敗。

| 項目 | 裝置 kernel | module build |
|---|---|---|
| compiler | Clang | GCC 12 |
| 型態 | `CONFIG_CC_IS_CLANG=y`、`CONFIG_LTO_CLANG=y`、`CONFIG_CFI_CLANG=y` | `CONFIG_CC_IS_GCC=y`、`CONFIG_CLANG_VERSION=0`、`CONFIG_LTO_NONE=y`，沒有 `CONFIG_CFI_CLANG` |
| 共同 | `CONFIG_MACH_ASUS=y`、`CONFIG_SHADOW_CALL_STACK=y`、`CONFIG_MODVERSIONS=y`、`CONFIG_MODULE_SIG` 未設、`CONFIG_PANIC_ON_OOPS=y` | 同左 |

build tree 以 ASUS 的 `33.0210.0210.296` source drop 為 base（那是 `5.4.147`，不是裝置的 `5.4.210-qgki-perf-g6e91db764350`／`.337`；ASUS 沒有為 `.337` 公布 source drop），再套 `ksu/patch/0003-zf8-kernel-side.patch`。這份 patch 動 12 個檔，其中三項決定 ABI：

1. `include/linux/module.h`：拿掉 `cfi_check` 的 `#ifdef CONFIG_CFI_CLANG`，以及 `jump_entries`／`num_jump_entries` 的 `#ifdef CONFIG_JUMP_LABEL`，讓這三個欄位無條件存在。
2. `include/linux/cfi.h`：把 `cfi_check_fn` 型別、`CFI_CHECK_FN`／`CFI_CHECK_FN_NAME` 巨集與 `extern void __cfi_check(uint64_t, void *, void *)` 宣告搬出 `#ifdef CONFIG_CFI_CLANG`（外層 `#ifdef CONFIG_MODULES` 保留）。少了這一步，第 1 項的欄位型別在 GCC build 裡沒有定義。
3. `scripts/mod/modpost` 的 `add_header()`：在產生的 `.mod.c` 裡，`__this_module` 初始器的 `.name`／`.init`／`.exit`／`.arch` 之後多吐一行 `.cfi_check = __cfi_check,`，讓 `this_module` 帶到 `0002` 的 stub 位址而不是 NULL。

這三項在 `patch/0003-zf8-kernel-side.patch` 內，其餘九個檔是同一個 patch 裡的建置相容修正（`-I$(src)` 的 trace／include 路徑、`asm("sp")` 的等效寫法、vendor 巨集的 fallback、`arch/arm64/Kconfig` 把 `STACKPROTECTOR_PER_TASK` 設成 `def_bool n`、`arch/arm64/Makefile` 移除對應的 `-mstack-protector-guard` 區塊）。`STACKPROTECTOR_PER_TASK` 這一項會改變模組引用 `__stack_chk_guard` 還是 `get_random_bytes`，漏了它建的模組 UNDEF 集合就不對，不影響 ABI。

**`sh_size == 0x3c0` 不是充分判據。** `struct module` 是 cacheline 對齊（arm64 為 64 bytes），少了 8 bytes 的 `cfi_check` 仍會進位成 960；`core_layout` 的對齊又把位移吸收掉，`cleanup_module` 的位置兩者相同。沒套 patch 的樹建出來的模組同樣是 `0x3c0`，差別只在 `init_module` 落在 `0x180` 而不是 `0x188`，以及沒有 `__cfi_check` 的 relocation。判據要同時看三個 relocation offset：`__cfi_check` = `0x108`、`init_module` = `0x188`、`cleanup_module` = `0x378`，`ksu/tools/ko_loadable.py verify` 第四項就在檢查這個。

這台裝置的 config 有 `CONFIG_JUMP_LABEL=y`，所以 `jump_entries`／`num_jump_entries` 本來就在；那個 guard 的改動在實際建置下是 no-op，留著只是為了與裝置源碼一致。真正讓佈局偏移的只有 `cfi_check` 一個欄位。

第三項改的是 `scripts/mod/modpost.c`，改完必須重編 modpost：`make M=` 不會因為 `modpost.c` 較新就重建它，此時 `.mod.c` 不會有 `.cfi_check`，而 `sh_size` 照樣是 `0x3c0`，錯誤會靜默通過。改完先 `make modules_prepare` 或刪掉 `scripts/mod/modpost` 二進位。

工具鏈是 `aarch64-linux-gnu-gcc-12` 與 `CROSS_COMPILE=aarch64-linux-gnu-`；換 compiler 會改變 UNDEF 集合，必須重新驗證三項條件與 UNDEF 數量。

| 變數 | 作用 |
|---|---|
| `CONFIG_KSU=m` | 把 `kernelsu.o` 建成 loadable module |
| `CONFIG_KSU_TRACEPOINT_HOOK=y` | 使用 `sys_enter` tracepoint 路徑；這台 kernel 的 kprobe 路徑不可用 |
| `CONFIG_KSU_MULTI_MANAGER_SUPPORT=y` | 啟用多管理器簽名表，讓 `EXPECTED_SIZE/HASH` 的自訂條目被編進去（`apk_sign.c:42-44`） |
| `KBUILD_MODPOST_WARN=1` | 對近 200 個未導出符號只警告（artifact 193 個）；不給則 modpost `rc=2` |
| `KSU_VERSION=35171` | `GET_INFO` 回報的版本碼；不給時用 `30000 + git rev-list --count HEAD + 700`，shallow clone 會先被 `Kbuild` unshallow，離線時才得不到同一個值 |
| `KSU_EXPECTED_SIZE=0x377` | 自訂管理器憑證的 DER 長度 |
| `KSU_EXPECTED_HASH=d3469712...` | 自訂管理器憑證的 SHA-256 |

```sh
KDIR=/path/to/5.4.210-kbuild-tree
make -C "$KDIR" M="$PWD/kernel" ARCH=arm64 \
  CROSS_COMPILE=aarch64-linux-gnu- CC=aarch64-linux-gnu-gcc-12 \
  KBUILD_MODPOST_WARN=1 \
  CONFIG_KSU=m CONFIG_KSU_TRACEPOINT_HOOK=y CONFIG_KSU_MULTI_MANAGER_SUPPORT=y \
  KSU_EXPECTED_SIZE=0x377 \
  KSU_EXPECTED_HASH=d3469712b6214462764a1d8d3e5cbe1d6819a0b629791b9f4101867821f1df64 \
  KSU_VERSION=35171 modules -j4
```

產物在 `kernel/kernelsu.ko`；此時 `__versions` 仍有 CRC，一批 UNDEF 尚未重定位。

### 2.3 `KSU_EXPECTED_SIZE`／`KSU_EXPECTED_HASH`

這兩個變數識別管理器 APK 的簽名憑證，與模組或 APK 的大小無關。`KSU_EXPECTED_SIZE` 是 APK v2 signature block 中第一個 signer 的第一個 certificate DER 長度，官方 ReSukiSU 是 `0x377` = 887 bytes（APK 檔本身是 9,379,362 bytes）；`KSU_EXPECTED_HASH` 是同一個 DER 的 SHA-256，64 個十六進位字元。Kbuild 傳成 `-DEXPECTED_SIZE` 與 `-DEXPECTED_HASH="..."`（`kernel/Kbuild:222-229`），`apk_sign.c` 在 `CONFIG_KSU_MULTI_MANAGER_SUPPORT` 下把 `{EXPECTED_SIZE, EXPECTED_HASH}` 加進 `apk_sign_keys[]`（`apk_sign.c:34-49`）。

另有一筆無條件存在的 `EXPECTED_SIZE_RESUKISU` = `0x377`／`d346...`（`manager_sign.h:21-22`）；對官方 APK 而言傳入同樣的 `KSU_EXPECTED_*` 是重複的，它的用途是讓自訂管理器有明確的編譯開關。配對別的憑證時必須同時設定這兩個變數並開啟 `CONFIG_KSU_MULTI_MANAGER_SUPPORT`。

artifact 的 `apk_sign_keys[]` 有 7 筆、沒有零結尾：6 筆上游（ReSukiSU `0x377`、tiann `0x33b`、5ec1cff `0x180`、rsuntk `0x396`、SukiSU `0x35c`、KOWX712 `0x375`）加第 7 筆自訂的 `KSU_EXPECTED_*`（與第 1 筆重複）。比對迴圈以 `ARRAY_SIZE` 巡覽（`apk_sign.c:168-177`），不需要哨兵；隨附的 manager APK 命中第一筆。

### 2.4 Post-build：`__versions` 的 `sh_size` 寫成 0

build tree 會把自身的 CRC 寫進 `__versions`，這些 CRC 從 build tree 的 `Module.symvers` 算出，與裝置 kernel 的 export 不一定一致。做法是直接改 section header 的 `sh_size`，資料留著不影響：

```sh
python3 - kernel/kernelsu.ko <<'PY'
import struct, sys
p = sys.argv[1]; d = bytearray(open(p,'rb').read())
shoff, = struct.unpack_from('<Q', d, 0x28)
shentsize, shnum, shstrndx = struct.unpack_from('<HHH', d, 0x3A)
stroff, = struct.unpack_from('<Q', d, shoff + shstrndx*shentsize + 0x18)
for i in range(shnum):
    o = shoff + i*shentsize
    nameoff, = struct.unpack_from('<I', d, o)
    end = d.index(b'\0', stroff + nameoff)
    if d[stroff+nameoff:end] == b'__versions':
        struct.pack_into('<Q', d, o + 0x20, 0); break
open(p,'wb').write(d)
PY
```

`objcopy --remove-section=__versions` 不可用（見 §1.2）。改完後重跑 §1.1／§1.2 的兩條 `readelf` 檢查。

### 2.5 Per-boot 的 UNDEF 重定位

模組引用約 193 個 build 時無法從 `Module.symvers` 解析的符號（`selinux_state`、`kallsyms_lookup_name`、`__tracepoint_sys_enter` 等），多數在裝置上不是 exported symbol。產物把它們標成 `SHN_UNDEF`，`simplify_symbols()` 用 kernel 的 export table 解析，找不到就 `-ENOENT`。

late-load 的做法是改寫 symbol table：把每個 UNDEF 的 `st_shndx` 改成 `SHN_ABS`（`0xFFF1`），`st_value` 改成本次開機的 runtime 位址。載入器看到 `SHN_ABS` 就不再解析，直接把 value 當絕對位址。位址來源是 `/proc/kallsyms`，必要時先把 `kptr_restrict` 設 0。

per-boot 的原因：KASLR 每次開機改變 kernel text/data base，link-time kallsyms 加該次開機的 delta 才是 runtime 位址。delta 從 exploit 的 log 取得，或直接讀該次開機的 `/proc/kallsyms`；驗證方式是 link-time kallsyms 加 delta 後第一行 `_text` 等於同一次開機 log 的 `runtime _text`。

工具在 `ksu/tools/`：`ko_absinfix.py`（逐一改寫 UNDEF 的 `st_shndx`／`st_value`，只處理 `SHN_UNDEF`）與 `ko_loadable.py build <in.ko> <link_kallsyms> <delta_hex> <out.ko>`（套 delta 產生 runtime kallsyms、呼叫前者、把 `__versions` 的 `sh_size` 寫成 0、檢查三項 ABI 條件與 UNDEF 是否全部重定位）。驗證 `aarch64-linux-gnu-nm -u out.ko | wc -l` 從 193 變 0。位址錯了，症狀是 `Unknown symbol`（解析失敗）或 `overflow in relocation type 275`（relocation 係數用了未重定位的 UNDEF 值），與 ABI 三條件失敗的症狀（`Exec format error`、oops、Live-but-dead）不同。

### 2.6 載入與最小驗證

```sh
insmod /data/local/tmp/ksu.ko allow_shell=1   # 以 exploit 的 root context 載入
grep '^kernelsu ' /proc/modules               # 期望：kernelsu <size> 0 - Live ...（只代表 ELF 被接受）
# 從 exploit 的 root server 跑 ksud 會回全 0：那個行程沒有 KSU 的驅動 fd。
# 真正的判據是開一次管理器後 dmesg 出現 install ksu fd：
#   KernelSU: [<pid>] install ksu fd: N
dmesg | grep "install ksu fd" | tail -3
```

`allow_shell=1` 讓 UID 2000 通過 `allowed_for_su` 的檢查（`kernel/policy/allowlist.c:260`），它是 module parameter、載入後持續有效；bring-up 後應在下次開機不帶它載入。

`/proc/modules` 的 `Live` 只證明 ELF 被載入器接受：adb 掉線時 `cat` 回空，會被誤報成已載入；而 §1.1 的 Live-but-dead 也會顯示 `Live`，所以 supercall 是否活著要看管理器能不能取得驅動 fd（`dmesg` 的 `install ksu fd`）。已有 `kernelsu` 時不要重複 `insmod`（`EEXIST`）。bring-up 時可先把 `/proc/sys/kernel/panic_on_oops` 設 0，讓 oops 可觀察。

---

## 3. 管理器配對

### 3.1 UAPI 版本

rc3 的 `uapi/supercall.h:20` 是 `KERNEL_SU_UAPI_VERSION = 4`。管理器 APK 的 native library 也回 4：對 `lib/arm64-v8a/libkernelsu.so` 的 `Java_com_resukisu_resukisu_Natives_getManagerUAPIVersion` 反組譯得到 `mov w0, #0x4; ret`。APK 的 versionCode 是 35171、versionName `v4.2.0-rc3`；模組的 `KSU_VERSION` 也是 35171（artifact 的 `do_get_info` 可見 `mov w1, #0x8963`）。versionCode 不是相容性閘，UAPI 才是。

`isFullFeatured` 要求 `kernelUAPIVersion == managerUAPIVersion`（`HomePage.kt:194-229`、`Natives.kt:205-207`）：kernel UAPI > manager 時顯示 `Manager update required`，反之顯示 `Kernel update required`（LKM 分支）。`ksud` 自己也檢查：`ensure_uapi_version_matched()` 在兩邊不同時 bail，訊息是 `UAPI version mismatch: kernel=X, ksud=Y. Please update KernelSU!`（`userspace/ksud/src/android/ksucalls.rs:199-208`）。

不要安裝 CI／HEAD 建置：release 停在 35171／UAPI 4，CI 建置不受 tag 約束，UAPI 可能已變；管理器的更新提示會把 CI build 當成新版本，安裝後可能出現 `Manager update required`，直到模組也從同一 revision 重建。

### 3.2 簽名憑證

`apk_sign_keys[]` 是 crowning 的信任清單（`kernel/manager/apk_sign.c:34-49`），官方 ReSukiSU 那筆是 `(0x377, d3469712...)`（`manager_sign.h:21-22`）。流程：

1. 模組 init 呼叫 `track_throne()`（`kernel/core/init.c:252`，套 `0001` 後；上游 rc3 是 `:247`），掃描 `/data/app`（`kernel/manager/throne_tracker.c:340` 的 `track_throne()`，掃描點在 `search_manager()` `:157`）。這個 build 開 `CONFIG_KSU_TRACEPOINT_HOOK`，`ksu_handle_rename()` 不編進模組（guard 在 `:357`），rename 不會重新觸發掃描。
2. `is_manager_apk()`（`apk_sign.c:403-418`）呼叫 `check_v2_signature()`（`:240-341`），解析 v2 block、取第一個 signer 的第一個 certificate DER，逐一比對表中的 `(size, sha256)`（`:168-177`）。
3. 命中時 `crown_manager()` 用 `/data/system/packages.list` 的 package↔uid 配對把 UID 註冊成 manager（`throne_tracker.c:32-51`）；之後 `is_manager()` 以呼叫者 UID 查這份清單（`kernel/manager/manager.c:47-50`）。

這個 build 沒有定義 `KSU_MANAGER_PACKAGE`，crowning 只比對憑證：任何安裝在 `/data/app`、帶同一張憑證的 APK 都會被視為 manager。

```sh
apksigner verify --print-certs ReSukiSU_v4.2.0-rc3_35171-arm64-v8a-release.apk
# Signer #1 certificate SHA-256 digest: d3469712b6214462764a1d8d3e5cbe1d6819a0b629791b9f4101867821f1df64
```

失敗模式：憑證不受信任時 `is_manager_apk()` 回 false，管理器不被 crown，首頁顯示 `Unsupported`，需要 manager 權限的操作得到 `Permission denied`，`GRANT_ROOT` 也被 `allowed_for_su` 拒絕（除非 `allow_shell=1` 或該 UID 在 allowlist）。憑證受信任但 APK 非官方簽名時 crowning 成功、功能可用，APK 自己的 `isOfficialSignature` 會顯示警告，不影響 kernel 側授權。

順序是先安裝 manager APK 再載入模組：crowning 發生在模組 init，而 `CONFIG_KSU_NO_OBSERVER=1` 讓安裝／更新 APK 不觸發 fsnotify 重新掃描。模組載入後才換 APK，必須重開機、重跑 exploit 鏈、重新 `insmod`。

---

## 4. supercall 升權

### 4.1 取得 KSU driver fd

`ksud` 先掃 `/proc/self/fd` 找 link target 是 `anon_inode:[ksu_driver]` 或 `anon_inode:[ksu_driver_su]` 的 fd，找不到才用 reboot magic；`ksugrant` 直接用：

```c
syscall(SYS_reboot, 0xDEADBEEF, 0xCAFEBABE, 0, &fd);
```

`0xDEADBEEF`／`0xCAFEBABE` 是 `KSU_INSTALL_MAGIC1`／`KSU_INSTALL_MAGIC2`（`uapi/supercall.h:23-24`）。這台裝置的 `sys_call_table` 不能打補丁（exploit 的 3 GB device 窗已映射表的 PA，第二重映射造成 SError），所以模組用 `sys_enter` tracepoint 攔截：`ksu_sys_enter_handler()` 看到 `__NR_reboot` 且 `regs[0] == 0xDEADBEEF` 時呼叫 `ksu_handle_sys_reboot()`，裝一個 anon-inode fd、把 fd 號碼 copy 回使用者指標，並把 `regs->syscallno` 設成 `-1`、`regs->regs[0]` 設成回傳值（成功為 0），讓真正的 reboot syscall 不執行（`kernel/hook/syscall_hook_manager.c:104-122`；`kernel/supercall/supercall.c:127-172`）。

fd 安裝不檢查 UID，權限閘在 ioctl：`GET_INFO` 是 `always_allow`，`GRANT_ROOT` 的 `perm_check` 是 `allowed_for_su`（`kernel/supercall/dispatch.c:1175-1187`）。

### 4.2 `KSU_IOCTL_GRANT_ROOT`

ioctl 編號 `0x4b01`（`_IOC(_IOC_NONE, 'K', 1, 0)`；`uapi/supercall.h:212`）。`allowed_for_su()` 是 `is_manager() || ksu_is_allow_uid_for_current(...)`（`kernel/supercall/perm.c:29-34`）；`is_manager()` 查 crowning 註冊的 UID，`ksu_is_allow_uid_for_current()` 查 allowlist 並在 `allow_shell` 為真時放行 UID 2000（`kernel/policy/allowlist.c:246-274`）。

通過後 `do_grant_root()` 呼叫 `escape_with_root_profile()`（`kernel/supercall/dispatch.c:44-56`、`kernel/policy/app_profile.c:160-245`）：`prepare_creds()` 複製 cred；`uid`／`suid`／`euid`／`fsuid` 設成 root profile 的 UID（預設 0），`gid`／`sgid`／`egid`／`fsgid` 設成 root profile 的 GID（預設 0）；effective／permitted／bset capabilities 設成 full set，effective 另加 `CAP_DAC_READ_SEARCH`（讓非 root 也能讀 `/data/adb/ksud`）；SELinux domain 設成 `u:r:ksu:s0`（`KSU_DEFAULT_SELINUX_DOMAIN` = `"u:r:" KERNEL_SU_DOMAIN ":s0"`，`KERNEL_SU_DOMAIN` = `"ksu"`；`kernel/policy/allowlist.c:49`、`kernel/selinux/selinux.h:12`）；`commit_creds()` 套用，`disable_seccomp()` 清 filter，並設 tracepoint flag 與 mount namespace。

完成後呼叫者自己就是 root，不需要 fork daemon 或傳 fd；`ksugrant` 接著 `execvp` 命令，root cred 延續到新程式。

### 4.3 管理器子行程的 fd 繼承

管理器 App 的 root shell 走 `libksud.so` 子行程，不是 `ksugrant`。兩個額外問題：預設 KSU fd 是 `O_CLOEXEC`，`exec` 後關閉，子行程要自己再取得；Android 13 的 zygote 在 `forkAndSpecialize` 為 App 裝 seccomp filter，`secure_computing()` 在 `trace_sys_enter` 之前執行，reboot magic 在到達 tracepoint 前就被 `EPERM`。

device patch 的處理：在 zygote→manager 的 `setresuid` 時（`id == 147`、`is_zygote(current_cred())`、新 UID 是 manager UID）安裝非 CLOEXEC 的 fd，並對 manager UID 抑制 `seccomp(2)`／`prctl(PR_SET_SECCOMP)`，讓 `libksud.so` 子行程能繼承 fd 並使用 reboot magic（`kernel/hook/syscall_hook_manager.c:124-170`）。這是 Android 13／5.4 的時序特定 workaround，`ksugrant` 從 shell 執行時不需要；代價是 manager UID 的 seccomp filter 被抑制，App sandbox 比原本弱。

---

## 5. 限制

1. **只對這個 kernel build 有效。** `sizeof(struct module)`、vermagic、CFI/SCS 佈局、符號位址都是 build-specific；換 firmware 或 kernel commit，或改 `CONFIG_MACH_ASUS`／`CONFIG_MODVERSIONS`，都要用新的 source 與 config 重建並重新驗證三項條件與 UNDEF 重定位，每次開機也要重做重定位與 `insmod`。

2. **沒有 kernel module signature。** 裝置的 `CONFIG_MODULE_SIG` 未設，沒有簽章閘；移植到 `CONFIG_MODULE_SIG_FORCE` 的裝置時必須用該裝置信任的 key 簽章並把 key 放進 kernel keyring。

3. **部分功能被關掉。** `CONFIG_KSU_NO_OBSERVER` 跳過 fsnotify 的 package observer，安裝／更新 APK 不會重新 crowning；`CONFIG_KSU_NO_SELINUX_HIDE` 跳過 5.4 上 ABI 不相容的 selinux hide。kernel 的 RPMh 路徑（`rpmh-rsc.c` 的 `write_tcs_reg_sync()` 等回讀／重試迴圈）沒有有界化，可能無界迴圈；這是穩定性風險，不是 ABI 問題，也不在這次的三份 patch 內。
