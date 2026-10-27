# Root My Zenfone

利用 Qualcomm KGSL／IOMMU 的三個缺陷，在 ASUS Zenfone 8 Flip（SM8350，Android 13，kernel
5.4.210-qgki-perf）上取得 kernel root，再交給一個核心模組持有，之後可以正常使用 KernelSU
家族的管理器。

<mark>本專案僅用於研究，使用後果將由使用者自行承擔</mark>
> CVE-2026-43499 在此專案建立初期，少有 5.4 相關實作案例，故在嘗試數次無果後決定放棄 43499

## 三個漏洞

- **CVE-2023-33107**（CWE-190）— SVM 範圍檢查的 `gpuaddr + size` 整數回繞，讓重疊的 GPU 映射
  繞過 rbtree 檢查。
- **CVE-2024-21468**（CWE-416）— `arm_lpae_map_sg()` 快速路徑丟棄 `-EEXIST`，失敗回滾因此清掉
  一個既有 PTE，打出 4 KB 的洞。
- **CVE-2024-23373**（CWE-416）— unmap 失敗後仍清除 `MAPPED` 並釋放 backing pages，留下 65,539
  個懸空 SMMU PTE，形成實體頁 UAF。

## 需求

| 項目 | 要求 |
|---|---|
| Host | Linux x86_64 |
| 交叉編譯器 | `aarch64-linux-gnu-gcc-12`（預設值；用 `POC_CC` 指定別的，用 `POC_ALLOW_ANY_CC=1` 放行非 12.4.0 的版本） |
| binutils | `aarch64-linux-gnu-` 前綴的 `nm`、`readelf`、`objdump`，以及 host 的 `strings` |
| Python | 3（`__versions` 的 `sh_size` 改寫與 per-boot 重定位） |
| adb | 任一近期版本 |
| 裝置 | Zenfone 8 Flip（ZS672KS／ASUS_I004D），Android 13，kernel `5.4.210-qgki-perf-g6e91db764350`，bootloader 鎖定 |
| 自編模組時另需 | Zenfone 8 Flip 核心源碼、`git`、`make` |

## 使用

**先安裝管理器，再載入模組**。crowning 發生在模組 `init`，而這個 build 關掉了
package observer，載入後才安裝的 APK 不會被重新掃描。

### 1. 建置 PoC

```sh
cd poc
./build.sh
cd ..
```

產出 `poc/kgsl_23373_poc_main`。`build.sh` 會檢查產物裡沒有 `trigger path disabled` 與
`privilege-write stage disabled` 兩個字串，任一命中就中止。

大小與 md5 隨工具鏈變動（`build.sh` 不保證位元可重現）。本專案以 `gcc 12.4.0-5`、Debian 13 glibc
建出 1009344 bytes、md5 `216fdf917ea3243b6048c9635f29ce21`。

### 2. 安裝管理器

```sh
adb install ksu/artifacts/manager-official-v4.2.0-rc3.apk
```

APK 的簽章憑證必須在模組的 `apk_sign_keys[]` 內，否則不會被 crown。

### 3. 取得 root

```sh
adb push poc/kgsl_23373_poc_main /data/local/tmp/
adb shell chmod 755 /data/local/tmp/kgsl_23373_poc_main
adb shell "cd /data/local/tmp && PKEY_HIJACK_ONLY=1 LEGACY_BLIND_WRITE=0 \
  setsid nohup /data/local/tmp/kgsl_23373_poc_main 256 192 20000 root \
  >> /data/local/tmp/wrapper.log 2>&1 < /dev/null &"
```

`PKEY_HIJACK_ONLY=1` 不是可選的。不設它會走完整路徑，多出 800 個 parked 子行程與
`task_struct` 掃描，那是另一條鏈，成功率和時間都不同（`measure/` 的 3 輪全部用它）。`setsid nohup`
讓 adb shell 結束後 PoC 繼續跑。

PoC 啟動時會清掉 `wdcmd`、`rootcmd`、`rootout`，不需要手動 `rm`。

`argv[1]` 必須是 256；`argv[3]` 是每次競態的 mmap 嘗試上限；`argv[4]` 是模式，出貨路徑為
`root`。

執行前確認：裝置最好已開機 60 秒以上、`MemAvailable` 高於 500 MB、沒有殘留的 PoC 行程、沒有上次
留下的 `/data/local/tmp/poc.lock`。執行期間不要切換 USB 模式。UAF 建立後 PoC 不會退出，失敗時停在
`uaf_pause()`；只有重開機能復原。

**root 命令通道沒有認證。** `/data/local/tmp/rootcmd` 是一個普通檔案，root server 把每一行交給
`/system/bin/sh -c`。任何能寫入它的行程都能以 root 執行任意命令，這在 shell 可寫
`/data/local/tmp` 的裝置上等於一個 root backdoor。用完就重開機，或依 `poc/README.md` 的順序送
release 動詞。

成功後 PoC fork 一個 root server，以 `/data/local/tmp/rootcmd` 收命令、輸出 append 到
`/data/local/tmp/rootout`。

**取得 root 後 PoC 會立刻把被改寫的 `__arm64_sys_pkey_alloc` 還原**，log 出現
`[PKEY-GO] stub restored: syscall 289 is inert again`。在此之前，任何能呼叫 syscall 289 的行程
都會直接變成 uid 0——那不是這條鏈的副作用，而是一個全域 root oracle，所以它不能留著。想保留
（除錯用）設 `POC_KEEP_STUB=1`，那會讓裝置在重開機前對所有行程都是 root。

### 4. 載入模組

`ksu/artifacts/kernelsu-zf8-rc3-officialkey.ko` 是重定位前的模板，有 193 個 UNDEF。載入前要用
本次開機的 `/proc/kallsyms` 把每個 UNDEF 改寫成 `SHN_ABS` 加 runtime 位址。工具在
[`ksu/tools/`](ksu/tools/)，用法見 [`ksu/README.md`](ksu/README.md) §2.5。

改寫後的檔案推上裝置，經 root 命令通道載入：

```sh
adb push ksu.ko /data/local/tmp/
adb shell "echo 'insmod /data/local/tmp/ksu.ko' >> /data/local/tmp/rootcmd"
adb shell "cat /data/local/tmp/rootout"
```

`insmod` 需要 `CAP_SYS_MODULE`，直接從 `adb shell` 執行會回 `Operation not permitted`。
`allow_shell=1` 會讓 uid 2000 也能呼叫 `GRANT_ROOT`，只在 bring-up 時使用。

`/proc/modules` 出現 `Live` 只代表 ELF 被載入器接受。supercall 是否活著，看開一次管理器之後
`dmesg` 有沒有出現 `KernelSU: [<pid>] install ksu fd`：

```sh
adb shell monkey -p com.resukisu.resukisu -c android.intent.category.LAUNCHER 1
adb shell "echo 'dmesg | grep "install ksu fd" | tail -3' >> /data/local/tmp/rootcmd"
adb shell "tail -4 /data/local/tmp/rootout"
```

從 exploit 的 root server 直接跑 `ksud debug info` 會回全 0：那個行程沒有 KSU 的驅動 fd，
而 reboot magic 在它身上到不了模組。`ksud` 的數字要在管理器啟動的行程裡才有意義。

## 修補狀態

三個缺陷在 Qualcomm `msm-5.4` `LA.UM.9.14.1.c26` 與 AOSP `kernel/msm` redbull 4.19 qpr3 均已修補。
本專案測試的 build（`.337`／kernel `5.4.210-qgki-perf-g6e91db764350`）不含對應修補。

修補必須包含 `kgsl_mmu_unmap()` 的提早返回與 free op 的 `MAPPED` 守衛；只套 Android Security
Bulletin（ASB）2024-07-01 的 ion／anon 兩個 commit 不夠。

## 文件

| 文件 | 內容 |
|---|---|
| [01-vulnerabilities](docs/01-vulnerabilities.md) | 三個缺陷的機制、為何必須串連、上游修補狀態與未修邊界 |
| [02-exploit-chain](docs/02-exploit-chain.md) | 七個步驟的利用流程、每步的判據與前置條件 |
| [03-limitations](docs/03-limitations.md) | 可觀測痕跡、訊號可信度、可靠性、可重現性與設計註記 |
| [04-resukisu](docs/04-resukisu.md) | 用核心模組持有 root：ABI 條件、建置、管理器配對與 supercall |
| [poc/README](poc/README.md) | PoC 的旗標、模式、預期輸出與執行紀律 |
| [ksu/README](ksu/README.md) | 模組建置、三項閘門、重定位與 crowning |
| [ksu/build.sh](ksu/build.sh) | 從 kernel source drop 端到端重建模組 |

## 授權

本 repo 分區授權：

| 路徑 | 授權 | 說明 |
|---|---|---|
| `poc/`、`docs/`、`README.md` | Apache-2.0 | 全文見 [`LICENSE`](LICENSE) |
| `ksu/patch/0002`、`0003`、`ksu/artifacts/*.ko`、`ksu/tools/`、`ksu/build.sh` | GPL-2.0-only | 只涉及 ReSukiSU 的 `kernel/`（`kernel/LICENSE` 是 GPL-2.0）與 GPL-2.0-only 的 kernel header；全文見 [`ksu/LICENSE.GPL-2.0`](ksu/LICENSE.GPL-2.0) |
| `ksu/patch/0001` | 混合 | kernel 的 hunk 是 GPL-2.0-only，`KernelRepository.kt` 的 hunk 是 GPL-3.0 |

ReSukiSU 同時掛兩份授權：repo 根是 GPL-3.0，`kernel/LICENSE` 是 GPL-2.0 並涵蓋
`kernel/` 底下全部。模組只從 `kernel/` 編，對的是 GPL-2.0-only 的 kernel header，所以是
GPL-2.0-only。逐項說明見 [`ksu/LICENSE`](ksu/LICENSE) 與 [`ksu/NOTICE`](ksu/NOTICE)。
