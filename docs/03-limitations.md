# 限制、偵測與設計註記

**基準。** `poc/kgsl_23373_poc.c`，8515 行，md5 `ba6ff0d5930c1348888f8fd99b0fa89f`。裝置核心原始碼為 ASUS `33.0210.0210.296` 的 `kernel/msm-5.4`；實際執行的是 `.337` build，原始碼不在專案內。核心檔案以子系統相對路徑引用，PoC 以 `kgsl_23373_poc.c:NNNN` 引用。`[推論]`、`[未重新量測]` 表示由原始碼、幾何或反組譯推得、未在裝置上直接量測。

---

## 1. 偵測與緩解

### 1.1 軟體帳與 SMMU 頁表分歧

KGSL 對每個 pagetable 記兩本軟體帳：`stats.entries`（成功映射的區間數）與 `stats.mapped`（位元組數）。map 時增加（`kgsl_mmu.c:371-373`），unmap 時減少（`kgsl_mmu.c:462-463`），經 sysfs 暴露為 `entries`／`mapped`（`kgsl_mmu.c:68-124`）。數字由驅動自己記，不從頁表回算。

`kgsl_mmu_unmap()` 的順序（`kgsl_mmu.c:460-467`）：呼叫 `pt_ops->mmu_unmap()` 並把回傳值存進 `ret`；無條件 `atomic_dec(&stats.entries)`、`atomic_long_sub(size, &stats.mapped)`；清除 `KGSL_MEMDESC_MAPPED`；回傳 `ret`。`mmu_unmap()` 只清掉部分 PTE 時，三份狀態互相矛盾：`memdesc->priv & MAPPED == 0`、軟體帳已扣減、SMMU 頁表仍有 valid PTE。

殘留 PTE 等於 `DANGLING_PAGES` = 65,539（`kgsl_23373_poc.c:2414`），由 `UAF_SIZE` 幾何與回滾範圍推得，未做頁表 walk。`[推論]` 這些 PTE 是 valid 的，GPU 存取會正常翻譯到已釋放的實體頁，因此 SMMU 不會發 fault；日誌中的 GPU page fault 來自掃描階段對未映射 IOVA 的存取。「沒有 SMMU fault」不能當成沒有 UAF。

| 可用手段 | 做法 | 判讀 |
|---|---|---|
| 核心 instrumentation | 走每個 pagetable 的頁表數 valid PTE，與 `stats.mapped >> PAGE_SHIFT` 比 | PTE 數大於軟體帳即「軟體已忘記的映射」 |
| 核心 instrumentation | 對每個 memdesc 檢查 `!(priv & MAPPED)` 但 `gpuaddr` 的 PTE 仍 valid | 直接命中 UAF 物件；成本較高，適合排程或清潔路徑取樣 |
| 只有 sysfs | 讀 `entries`／`mapped` | 單獨無意義：正常 free 也會下降，需與 memdesc 數量或頁表佔用交叉比對 |
| 無核心權限 | §1.2 的日誌序列（`map without unmap`、`map sg err`、`unmap err`）或 tracepoint 生命週期 | 間接證據，兩者組合後鑑別力高 |

軟體帳扣減後，`kgsl_mmu_put_gpuaddr()` 因 `unmap_fail != 0` 跳過 `put_gpuaddr()`（`kgsl_mmu.c:408-409`），SVM region 留在 rbtree；`memdesc->gpuaddr` 仍被清零（`kgsl_mmu.c:419-420`）。同一個 hostptr 因此無法重新 import，region 洩漏到 process 結束。

### 1.2 錯誤路徑日誌

| 訊息 | 產生點 | 觸發條件 | 鑑別力 |
|---|---|---|---|
| `map without unmap` | `io-pgtable-arm.c:386`，`WARN_RATELIMIT(1, ...)` | `arm_lpae_init_pte()` 看到 PTE 已 valid 回 `-EEXIST`；fast path 丟棄回傳值 | 高，被 ratelimit；需確認 stack 經過 `arm_lpae_map_sg` 或 `__arm_lpae_map` |
| `WARNING ... __arm_lpae_unmap` | `io-pgtable-arm.c:813`（`.296`）；build 回報 840 | unmap 走到無效頁表項，`WARN_ON(!pte)` | 高，前提是 stack 經過 `kgsl_ioctl_gpuobj_free`；以 `__arm_lpae_unmap+0x894/0x918` 比對，不要硬編行號 |
| `kgsl kgsl-3d0: unmap err: 0x..., 0x..., 0` | `kgsl_iommu.c:353` | `iommu_unmap()` 回傳位元組數小於要求；末位是 `unmapped` | 高；`unmapped = 0` 表示一個 PTE 都沒清 |
| `kgsl kgsl-3d0: map sg err: 0x..., N, flags, 0` | `kgsl_iommu.c:373-379` | `iommu_map_sg()` 回傳 0，回滾後沒留下映射 | 中高；正常圖形負載不應出現 |
| `_get_svm_area: ... failed error -12` | `kgsl.c:4152-4155` | 找不到可用 SVM gap（`-ENOMEM`） | 低到中；競態沒命中的路徑，不是 UAF |
| `_get_svm_area: ... failed error -19` | 同上 | 重疊映射進入 `kgsl_mmu_map()` 後失敗（`-ENODEV`） | 中高；與 `map sg err` 同時出現才代表洞已打出 |
| `vmalloc: allocation failure: 36028797018961896 bytes` | `kgsl.c` 的 `kvcalloc`；`warn_alloc` | import 的 `priv_len` 讓 `memdesc_sg_virt()` 要求約 2^55 位元組 | 高，數字本身幾乎是簽名；`warn_alloc` 全域 ratelimit（約 1 次/10 秒） |
| `GPU PAGE FAULT: addr = ... pid= ...` | `kgsl_iommu.c:661-663`，`__ratelimit` | GPU 打到未映射的 IOVA | 低；正常 App 也會，量測用 tracepoint |

一次成功觸發留下同一 PID、約 15 毫秒內的序列：兩次 `map without unmap`、`map sg err`、`__arm_lpae_unmap` 的 WARN、完整 free stack（`__arm_lpae_unmap` → `arm_lpae_unmap` → `arm_smmu_unmap` → `iommu_unmap` → `kgsl_iommu_unmap` → `kgsl_mmu_unmap` → `kgsl_mmu_put_gpuaddr` → `kgsl_mem_entry_destroy` → `kgsl_ioctl_gpuobj_free`），最後 `unmap err ... 0`。

### 1.3 生命週期 tracepoint

| Tracepoint | 產生點 | 定義 | 欄位 | 用途 |
|---|---|---|---|---|
| `kgsl_mem_alloc` | `kgsl.c:3593` | `kgsl_trace.h:402` | `gpuaddr`, `size`, `tgid`, `usage`, `id`, `flags` | 配置時的原始大小與 flags |
| `kgsl_mem_mmap` | `kgsl.c:4233` | `kgsl_trace.h:434` | `useraddr`, `gpuaddr`, `size`, `usage`, `id`, `flags` | mmap 時的 `memdesc.size` |
| `kgsl_mem_free` | `kgsl.c:2224`、`kgsl.c:2347` | `kgsl_trace.h:528` | `gpuaddr`, `size`, `type`, `fd`, `tgid`, `usage`, `id` | free 時的物件 |
| `kgsl_mmu_pagefault` | `kgsl_iommu.c:650` | `kgsl_trace.h:823` | `device_name`, `page`, `pt`, `name`, `op` | 在 `__ratelimit`（`kgsl_iommu.c:657`）之前觸發，比日誌完整 |

**關聯規則**：對同一個 `id` 比較 `kgsl_mem_alloc.size` 與 `kgsl_mem_mmap.size`。正常兩者相等，因為 `get_mmap_entry()` 檢查 mmap 長度等於 footprint 或 size（`kgsl.c:3951-3964`）；這個檢查讀的是已被腐化的 `memdesc.size`，所以會通過，而 tracepoint 保留的是配置時與 mmap 時的兩個值。不相等就是 memdesc 被改寫的直接證據；這條鏈的差距是 4 KiB 對 3 GiB。

**sysfs 輔助訊號。** `gpumem_mapped`（`kgsl_sharedmem.c:160-166`）是 process 目前 VMA 映射的 GPU 記憶體總量，`kgsl_mmap()` 以 `memdesc.size` 累加（`kgsl.c:4229`），victim 被改成 3 GiB 後跳增 3 GiB。`gpumem_unmapped`（`kgsl_sharedmem.c:168-179`）在 `gpumem_mapped > gpumem_total` 時回 `-EIO`，對 4 KiB 配置做 3 GiB mmap 會造成這個條件。`pagetables/<name>/entries`、`/mapped` 是同一組軟體帳（見 §1.1）。這些檔案是 `0444`，SELinux label 與可讀性取決於裝置政策；當特權 daemon 的資料源，不要當一般 App 遙測。

**取樣成本。** 高 fault 負載會灌滿 ring buffer，上線前要調 per-CPU buffer 與丟棄策略；`kgsl_mem_alloc`／`kgsl_mem_mmap` 的頻率與 GPU 物件數成正比，噴射階段每秒數千筆，過濾要下在 kernel 端。

### 1.4 不可靠的訊號

**裝置端與核心日誌都會丟行。** 同一 binary、同一設定跑出來的 log，行數每次不同；缺行原因未定案，只保留「行確實會被丟」。PoC 因此預設不寫 f2fs log，改走 stdout/pipe（`kgsl_23373_poc.c:4536-4539`）；只在階段邊界 `fsync`（`:114-121`），高壓階段把 `sync()`／`fsync()` 變成 no-op（`:82-113`）；verdict 寫到 tmpfs 的 `/dev`（`:5626`）。核心側另有 `dmesg` 被 SELinux 擋、`printk` ring buffer 覆寫、`WARN_RATELIMIT` 與 `__ratelimit` 抑制重複訊息；`panic_on_warn=1` 時第一個 WARN 就重開機。這台裝置是 `panic_on_warn=0`（實測），WARN 可以存活。

**`ps` 看不到部分 process，自己也會崩。** 鏈以 `override_creds(&init_cred)` 取得 root：payload 在 `kgsl_23373_poc.c:5474-5511` 組出 `adrp`／`add`／`b override_creds`，由 `:5616` 的 `syscall(289)` 觸發，SELinux SID 換成 `init_cred` 的 SID，實測為 `uid=0(root) ... context=u:r:kernel:s0`。`adb shell` 是 `u:r:shell:s0` / uid 2000，看不到 `u:r:kernel:s0` 的 process；uid 0 本身也不是證據，init、vendor daemon、`adbd` 的 root 子行程都可能是 uid 0。`ps` 在這種狀態下自己也會崩，backtrace 是 `strncasecmp → parse_ko → comma_args → default_ko → ps_main`，崩潰後 pipeline 可能回傳 0，讓「process 數」變成假零。

**`comm` 只有 15 個字元。** `/proc/<pid>/comm` 顯示 `TASK_COMM_LEN - 1 = 15` 字元。PoC 的 process 名剛好 15 字元（`kgsl_23373_poc_`，`kgsl_23373_poc.c:148` 的 `strncmp` 就是 15 字元），用比 15 字元更長的 binary 全名（`kgsl_23373_poc_main`）比對 comm 永遠不命中；噴射子行程另外改名（`:2110`），只比對單一前綴會漏掉整族。

**計數器可能是使用者空間旗標。** `g_pkey_call_inflight` 是 PoC 在使用者空間包住 `syscall(289)` 的旗標（`:5569-5571`、`:5611-5616`），核心 payload 只有 `adrp`／`add`／`b` 三條指令、沒有 store，量到 0 不代表 payload 沒執行。`[PKEY] VERDICT=PASS`（`:5678`）與 `[PKEY-GO] rooted fastpath`（`:5715`）都是 PoC 自己寫的；後者只在 `getuid() == 0` 之後印，比其他 marker 強，仍是使用者空間宣稱。`dangling: [0x700200000, 0x710203000)（65539 頁）` 是從常數算出來的，只能當幾何確認。

**「UAF established」不檢查 errno。** 這行只證明重新 import 同一個 hostptr 失敗；若 unmap 其實成功，重新 import 也會失敗，因為原本的 VMA 已被 `munmap`（`kgsl_23373_poc.c:2629`）。`errno == 12`（rbtree 重疊的 `ENOMEM`）才是 UAF 特有訊號，程式碼層面的判別器比它宣稱的弱（`:2655-2658`）。

**位址與行號會漂移。** KASLR 讓絕對位址每次開機不同，PoC 用 leak 到的 `kgsl_pool_ops` 推算 slide（`:5332-5335`）。`.296` 與 `.337` 相差兩行（`WARN_ON(!pte)` 在 838 vs 840），用函數名、offset、訊息字串比對。`__arm64_sys_pkey_alloc` stub 在 link-time 是 `0xffffffc010313994`（`:5469`），前兩個 word `928004a0 d65f03c0`（`mov x0, #-ENOSYS; ret`）是比對目標，不是位址。

### 1.5 緩解

修補內容與優先序見 `01-vulnerabilities.md`。兩個要點：只套 ASB 2024-07-01 點名的 anon/ion 修補擋不住這條鏈，目標物件走 pool free 路徑（`kgsl_sharedmem.c:1001-1015`、ops 表 `kgsl_sharedmem.c:1056-1062`）；驗證修補要看 binary——對 `kgsl_mmu_unmap` 反組譯確認 `mmu_unmap()` 的回傳值有被 branch，對 `kgsl_free_pool_pages` 反組譯確認 free 前有讀 `memdesc->priv` 並測試 `MAPPED`。

裝置 `.296` 的兩個對照點：`kgsl_mmu_unmap`（`0xffffffc010a14220`）的呼叫點是 `blr x19; mov w19, w0; b ...`，沒有 branch；`kgsl_free_pool_pages`（`0xffffffc010a20198`）沒有讀 `priv`。修補後應看到「`blr` 之後有條件分支」與「free 前有 `ldr` 加 `tbnz`/`tbz`」。位址隨 KASLR 移動，比對指令序列。

| 措施 | 效果 | 代價與限制 |
|---|---|---|
| `panic_on_warn=1` | 第一個 `map without unmap` 就重開機，把鏈停在造洞階段 | 任何驅動的 WARN 都會重開機；`WARN_RATELIMIT` 可能在窗口內抑制 `__warn()`；揮發性日誌消失 |
| SELinux `allowxperm` 限制 `/dev/kgsl-3d0` 的 ioctl | 對 shell 或 untrusted_app 擋掉 `GPUOBJ_IMPORT` 或超大 `GPUOBJ_ALLOC` | 破壞合法 buffer import/alloc；App domain 本來就需要 GPU 存取，對惡意 App 不是邊界 |
| seccomp 擋 `pkey_alloc`（syscall 289） | 在 exploit 之前安裝時，最後一步被拒 | per-process 且繼承，對 `adb shell` 無法外部施加；只擋最後一步，不修 UAF |
| 核心 text 完整性監控（stub 是否仍為 `928004a0 d65f03c0`） | 抓到 root 前的最後一個動作 | 需要 EL3/hypervisor 或特權模組；此裝置 `CONFIG_KPROBES`、`CONFIG_DEBUG_FS` 未設，沒有現成的核心內 probe 介面 |
| tracepoint/eBPF 監控 | mmap 時抓到 4 KiB → 3 GiB 的 size 不一致，在物理窗被使用前告警 | 需要特權 daemon、buffer sizing、SELinux 政策；屬偵測，不屬預防 |
| `kptr_restrict=2`、隱藏 kallsyms | 幾乎無效 | slide 來自 UAF leak 的 `kgsl_pool_ops`（`:5332-5335`），不是 kallsyms |
| KASLR、CFI、W^X、PAN、hardened usercopy、SLUB 硬化、`init_on_alloc` | 已在裝置上開啟 | 對「第二個 user-RW PTE 指向同一實體頁」無效：寫入不經過核心 VA 權限；`pfn_modify_allowed()` 在 arm64 走 generic stub、回傳 true |
| memory cgroup / GPU 配額 | 理論上限制噴射 | KGSL pool pages 是核心配置，不計入 process 的 memcg；256 MiB 與 69,632 個物件不受 per-app 上限影響。`[推論]` |

### 1.6 防禦方檢查清單

修補驗證（source + binary）：

source 檢查見 `01-vulnerabilities.md` §10.1，binary 比對見 §1.5。

執行期與事件回應（訊號定義見 §1.2、§1.3）：

- [ ] 告警規則要求「`unmap err` 的 stack 含 `kgsl_ioctl_gpuobj_free`」或「`map without unmap` 加 `__arm_lpae_unmap` 在同一 PID、短窗口」，不要只看單行；日誌被丟、ratelimit、`ps` 崩潰都不應讓規則失效。
- [ ] 用 eBPF/perf 接 `kgsl_mem_alloc`／`kgsl_mem_mmap`／`kgsl_mem_free`，對同一 `id` 比對 alloc 與 mmap size，差值超過一個數量級告警。
- [ ] 監控 `gpumem_mapped`／`gpumem_unmapped` 的 `EIO` 與跳增；監控 pagetable 的 `entries`／`mapped` 並與頁表 walk 交叉比對。
- [ ] 對 uid 0 但 SELinux domain 不是 `init`／系統域的 process 告警；用 `ps -Z` 或核心審計。
- [ ] 監控 `/sys/fs/selinux/enforce` 的 Enforcing → Permissive 與 `audit_enabled` 的 1 → 0 轉變，並要求有對應的 `setenforce` 操作。
- [ ] 檢查 `/proc/<pid>/maps` 是否有 1–3 GiB 的 `/dev/kgsl-3d0` VMA；`VM_DONTDUMP` 生效，core dump 不含它。
- [ ] 重開機前保存 pstore/ramoops、console、`logcat -b kernel`、`/proc/modules`、`getenforce`、`ps -Z`、`/proc/<pid>/maps`、`/sys/devices/virtual/kgsl/proc/*`。
- [ ] 看到 `unmap err` 加 free stack，假設「有頁被釋放但 PTE 還在」，先取證再重開機。

---

## 2. 可靠性

### 2.1 成功率

| 組態 | 結果 | 性質 |
|---|---|---|
| 出貨組態（`measure/shipping_20261027T155404Z`） | 3/3 回合判 GO，平均 28.3 s | binary `216fdf91…`、source `ba6ff0d5…`，兩者就是隨附的檔案；3 輪 3 次嘗試，無重試。存檔沒有 `rootout` 原文；取得 root 後自動還原 pkey stub，另用 `syscall(289)` 探針確認已失效、root 通道仍回 uid=0 |
| 前一代組態 | 統計已撤回，不引用為成功率 | 分母排除了卡死輪，失敗分類也缺該類 |
| 更早的組態 | 沒有保留存檔，不引用 | 當時的瓶頸是 reclaim 的物理抽籤與掃描覆蓋 |
| 裝置自崩基線 | 5–10% | SMMU fault、GPU power collapse、電池窗口撞期 |
| 三次開機重試 | 1 − p³ = 99.9%–99.99% | 由基線推導的算術，不是量測值 |
| 競態命中 | 約 90–100%/boot | 單一裝置統計 |

「100%」只在那個系列、那個 build、那個環境成立；量測儀表量的是 root server／uid 0 行程，不是 hijack 本身。PoC 內部的門檻：競態最多 3 次嘗試、每次間隔 10 秒（`kgsl_23373_poc.c:2661`、`:2686-2689`）；噴射最多 69,632 個物件（`:5011`），每 4,096 個掃描一次（`:5066`）；`syscall(289)` 最多 4 次，每次換 CPU 並做 I-cache 驅逐（`:5581`、`:5595-5612`）；UAF 建立後任何關鍵步驟失敗都進 `uaf_pause()`，不繼續、不退出（`:192-198`）。

### 2.2 時間

| 項目 | 值 | 依據 |
|---|---|---|
| 競態窗口 | 2–13 ms | `warn_alloc` 的 `dump_stack`/`show_mem`；`kgsl_23373_poc.c:2651-2658` |
| 競態前的 ratelimit 重置 | 10 s | `sleep(10)`（`:2657-2658`） |
| 唯讀掃描單趟 | 約 0.5 s（65,539 頁） | `:3240-3243` |
| 心跳週期 | 2 s | `:2880` |
| GPU idle 崩潰門檻 | 約 3 s | `:4673-4674` |
| 開機後 settle | 60 s | `:1502-1515` |
| 從鏈啟動到 uid 0 | 25–30 s（3 輪，平均 28.3 s） | `measure/shipping_20261027T155404Z`；單一裝置、單一環境 |

兩個 root 時間的基準不同，不能相加或互比；掃描與噴射取決於 reclaim 的命中速度，典型在數十秒內完成，沒有硬性上界。

### 2.3 量測紀律

- **判據用命令往返。** 寫一條命令到命令通道，看到 `uid=0(root)` 的回應才算 root；日誌行、`ps` 輸出、使用者空間旗標都不能單獨當判據。
- **一輪一個 binary。** 每輪開始前在 host 與 device 各算一次 md5，一致才啟動；保留該輪的 md5、旗標、boot id、啟動命令與日誌。不同 binary 的輪次不合併統計。
- **量測期間不碰裝置。** 不加 adb 命令、不截圖、不拉 log、不換 USB 模式；這些都會改變排程、allocator 與 cgroup 狀態。
- **A/B 必須交錯。** 同一組態連續跑會受批次效應影響；兩個變體交替執行，一次只改一個變數。
- **完整鏈每次從乾淨開機開始。** 殘留的核心物件、SVM region 與 pool 狀態會改變物理抽籤；只有競態本身允許在同一次開機內重試 3 次。
- **不要用 uptime 歸零當崩潰證據。** 任何會呼叫 `adb reboot` 的觀測腳本都會製造出這個假象；觀測器不得重開被測裝置。
- **reboot 後先確認 adb 就緒。** 以一次命令往返確認，不要用 `sleep` 代替；沒就緒就啟動會把無效輪記成鏈失敗。
- **分母要包含所有啟動輪。** 失敗、卡死、裝置自崩、adb 失聯都要記，只算乾淨輪會把成功率算高。
- **量測前先驗證儀表自洽。** 用零工作對照：同一設定相隔一段時間連跑兩次，結果必須相同；不同就代表儀表或環境有問題。
- **單例鎖。** 兩個 chain 會搶同一個固定 dangling 窗，輸家看到全零，root 時間加倍（`kgsl_23373_poc.c:4441-4447`）；鎖搶不到時應在碰 GPU 之前退出。

### 2.4 失敗模式分類

| 失敗 | 可觀測徵象 | 處置 | 出處 |
|---|---|---|---|
| 競態 miss | `_get_svm_area ... -12`；重 import 成功 | 睡 10 秒重試，最多 3 次 | `kgsl_23373_poc.c:2661-2691` |
| `warn_alloc` 額度被吃掉 | import 在微秒內失敗 | 同上；先睡 10 秒保證第一次是慢路徑 | `:2651-2658` |
| 重疊映射沒打出洞 | `ok>=5` 提前跳出，`enodev` 仍為 0 | 由重 import 判別器兜底 | `:2667-2670` |
| GPU idle 導致 power collapse | 約 3 秒無 submit 後裝置死亡 | 心跳每 2 秒送 `[NOP, CP_WAIT_MEM_WRITES, NOP]` | `:2865-2880`、`:4673-4674` |
| 電池窗口撞期 | GPU submit 與 SPMI/ksys_sync 並發後停住 | `wait_clean_band()` 等到窗口過去 | `:1502-1531`、`:2865-2869` |
| f2fs sync 卡死 | `sync()`／`fsync()` 永久不返回 | 高壓階段 no-op，只在階段邊界 fsync | `:81-119` |
| `syscall(289)` 不返回 | 卡在 syscall exit，不在 payload | watchdog 接手；`g_pkey_ret` 留在記憶體 | `:5569-5571`、`:4300-4302` |
| 低 bank mmap 失敗 | `errno=12`，`g_lb` 為 `MAP_FAILED` | 停泊，不設定 `g_lb` | `:5415-5425` |
| δ 或 ops 不合格 | 候選的 size/gpuaddr/flags 三重比對失敗、delta 非 2 MB 對齊 | fail-closed，停泊 | `:5304-5322`、`:5332-5335` |
| stub 不是預期值 | `st0/st1` 不符 | 跳過 patch，fail-closed | `:5516-5523` |
| reclaim 抽籤 miss | 掃描 0 命中 | 繼續噴射到 69,632 或 EMA 超標 | `:5036-5051` |
| 掃描批次 fault | `errno` 非 0 | 批次砍半，原地重試；最小 8 頁 | `:3309-3318` |
| 窗撕裂 | 候選全髒（`nx=0x8c`） | 64 次 fault 後放棄掃描 | `:7121-7123` |
| root server 被 cgroup 殺 | server 靜默消失 | 保活子行程接手命令通道 | `:2158-2174` |
| teardown 硬凍結 | 最後一個 fd 關閉後停住 | 保留一個 fd 持有者，不讓 `f_count` 歸零 | `:3589-3593` |

---

## 3. 可重現性

### 3.1 建置

`poc/build.sh` 是建置權威，不要手抄編譯命令：

```sh
aarch64-linux-gnu-gcc-12 -O2 -static \
    -DV7_ENABLE_TRIGGER=1 -DV7_ENABLE_PRIV_WRITE=1 \
    -DV7_ENABLE_RELEASE_EXIT=${RELEASE_EXIT:-0} \
    -DROSCAN_WAIT_RETIRE=${ROSCAN_WAIT_RETIRE:-1} \
    -o "${1:-kgsl_23373_poc_main}" kgsl_23373_poc.c -lpthread -ldl
```

| 旗標 | 預設 | 作用 |
|---|---|---|
| `-O2` | 固定 | 不要用 `-O0`/`-O3` 做「等價」重建 |
| `-DV7_ENABLE_TRIGGER=1` | 原始碼預設 0 | 啟用觸發/鏈路徑；少了它以 RC=2 退出，字串是 `trigger path disabled in this build` |
| `-DV7_ENABLE_PRIV_WRITE=1` | 原始碼預設 0 | 啟用 SELinux/credential 寫入階段；少了它會印 `privilege-write stage disabled at compile time` 並繼續，落到停泊，外觀與「鏈卡住」相同 |
| `-DV7_ENABLE_RELEASE_EXIT` | 0 | 把 `RELEASE_EXIT` 編進去；其餘 release 動詞不受影響 |
| `-DROSCAN_WAIT_RETIRE` | 1 | 掃描的 submit→讀回之間是否有同步點；0 的結果在多輪之間不自洽 |
| `-static` | 固定 | 把 glibc 版本寫進 binary |

建置後的兩項字串檢查（`build.sh` 的一部分）：`strings "$OUT" | grep -q "trigger path disabled"` 與 `... "privilege-write stage disabled"` 都必須不命中。

### 3.2 基準產物

| 項目 | 值 |
|---|---|
| 原始碼 | `kgsl_23373_poc.c`，8515 行，md5 `ba6ff0d5930c1348888f8fd99b0fa89f` |
| 預設旗標的建置產物 | 1009344 bytes，md5 `216fdf917ea3243b6048c9635f29ce21` |
| 編譯器 | `aarch64-linux-gnu-gcc-12` 12.4.0-5（Debian） |

產物 md5 在 2026-10-21 以 `poc/build.sh`（預設 `RELEASE_EXIT=0`、`ROSCAN_WAIT_RETIRE=1`）重建後核對。

### 3.3 可重現性的邊界

位元級可重現需要：相同的原始碼 md5、相同的編譯器與 glibc（`-static` 把版本寫進 binary）、相同的 `-D` 旗標、相同的原始碼檔名。檔名會以 STT_FILE symbol 進 binary（`readelf -s` 可見 `FILE ... kgsl_23373_poc.c`）；改名再編，md5 會變，即使程式碼一字未改。

裝置側需要：同一個 kernel build、同一組 config、4 KiB page size、同一個 `struct` 佈局、同一組 SVM 範圍與 `KGSL_IOMMU_VA_BASE64`、乾淨開機、沒有其他 kgsl client、沒有殘留命令檔。會改變數字但不改變程式碼的因素：KASLR slide、`memstart_addr`、`physvirt_offset`、`kimage_voffset`、allocator 狀態與 pool 的 LIFO 內容、cred_jar 的 partial slab、電池窗口相位、裝置溫度與 GPU 電源狀態。

---

## 4. 設計註記

### 4.1 GPU 命令通道與快取可見性

type-7 封包的 32-bit 標頭是 `0x70000000 | cnt | parity(cnt)<<15 | op<<16 | parity(op)<<23`：`cnt` 在 bit 0–14，bit 15 是 `cnt` 的 parity，`op` 在 bit 16–22，bit 23 是 `op` 的 parity（`kgsl_23373_poc.c:2506-2515`）。已驗證的是 bit 15，方向與常見教科書相反：實測符合偶校驗 `parity(x) = 1 ^ (popcount(x) & 1)`，popcount 為偶數時置位（`:2509-2511`）。bit 23 未驗證：同一規則套在 `op` 會失敗，`cp_wait_mem_writes` 的 `op=0x92` 實際 bit23=1，規則預測 0（`:2512-2513`）。標頭算錯時 firmware 直接拒收 IB，後續 submit fault（`:2514-2515`）。

寫 dangling VA 用 `CP_MEM_WRITE`（0x3D）；`CP_MEMCPY`（0x75）的寫入不生效（`:2498-2499`、`:2523`）。讀取用 `CP_MEMCPY`（0x75）（`:2523-2531`），另有 `CP_MEM_TO_MEM`（0x73）作等價讀取（`:2533-2540`），只在 0x75 失敗時整組改用，用來區分「沒有讀權限」與「封包／緩衝問題」（`:3192-3195`）。

8-byte、count-4 的寫入封包實測無效或可能 fault，因此 `ops` 指標拆成兩個 32-bit、count-3 的封包寫入（`:8234-8235`、`:8251-8252`）；`size` 是唯一以 count-4 64-bit 封包寫入的欄位（`:8243`）。

核心在每次 submit 尾端附 `CP_EVENT_WRITE CACHE_FLUSH_TS`；retire 代表 GPU L2 flush 完成，比盲等確定（`:2354-2356`）。retire 不是「指令已執行」的證明：核心有路徑以 CPU 直接寫 memstore 推進時間戳。關鍵寫入前會跑 GPU 金絲雀：寫入、等 retire、讀回比對（`:3416-3419`）。`last_submit_ts` 是 `__thread`，心跳執行緒的 submit 不在呼叫端保證內，等到的可能是過期或初始 timestamp（`:2363-2369`）。

`setup_ib()` 配置一個 context 與一個 GPU 物件當 IB；每次 submit 前把封包寫進 IB 的 CPU 映射，submit 後核心附加時間戳封包，`wait_submit_retire()` 以 `WAITTIMESTAMP_CTXTID` 等待（`:2370-2373`）。submit fault 走 `rebuild_ctx()`：固定 5 次 ×300 ms，只檢查 `ioctl()==0`，不分辨 errno（`:2778-2788`）；重建後要用新的 ctx 與 timestamp。

GPU 寫入先落在 L2／LLCC，之後才回寫 DRAM；churn 的用途就是把目標 line 推到 DRAM（`:3016-3017`）。marker 驗證不需要額外 cache flush：marker 位於自己的 cache line（`:2925-2927`）。更危險的是 CPU 的 stale line 回寫：`SET_INFO` 對 `flags@+0x50` 做 read-modify-write，而 `flags` 與 `ops@+0x48` 共用同一條 cache line；storm 把 line 逐出到 DRAM 後，RMW 取回的 line 會帶著 GPU 的值，但 CPU 端 stale 副本的首次讀取會把 line 標成 dirty，之後的 writeback 仍會蓋掉 GPU 的值（`:2473-2476`、`:8338-8339`）。

memdesc 改寫成功後，不要對同一個 memdesc 發 `INFO`／`SET_INFO`／probe：首次讀取會把 stale line 標成 dirty（`:8269-8271`）。驗證只走 1 頁的 `ops` 探針與 `0x91005a4d` magic 讀（`:8338-8343`）。完整序列是：GPU 端 churn 把 LLCC 填滿、把目標 line 推到 DRAM（`:3016-3017`）；逐核 pin 的 CPU storm 以 64 B stride 重寫 8 MiB 映射、每核 40 輪，逐出各核的 stale 副本（`:3058-3068`）；最後用 `INFO` 的 size gate 取回 line 0x00，隨即 mmap 加 deref（`:8341-8343`）。spray 頁的識別字在 `+0x00`、GPU marker 在 `+0x800`，兩者不同 cache line，讀 marker 時那條 line 是乾淨的（`:2419-2422`）。

### 4.2 核心 text 與記憶體原語

**device 映射的寫入不 snoop I-cache。** `ic ivau` 在 device-type 別名上是 NOP（或 UNPREDICTABLE）；位址無關的 `ic ialluis` 需要 EL1+，UCI 不豁免 IALLUIS，EL0 執行會 SIGILL。檔案記錄了這條路徑造成的 abort 與未 heal 的 teardown 連鎖（`kgsl_23373_poc.c:1743-1745`、`:1818-1820`）。

**EL0 可用的原語。** `dc civac` 把 dirty 的 D line 清出 L1D，`ic ivau` 踢掉本核的 I line（`:1727-1729`）；容量逐出負責 L2 與獨立的 L1I：以 64 B stride 順序讀 16 MiB（超過 SM8350 各核的 L2），再用 256 KiB 的 RET 指令 sled 以 64 B stride 逐行執行（`:1747-1751`、`:1762-1765`）。

**跨核重試與成本。** 每次嘗試釘到不同的 allowed core；同一條 64 B line 可能已在某核的 L1I 裡，device 窗的寫入不會讓它失效（`:5573-5576`、`:5595-5604`）。每次嘗試觸及 16 MiB 寫、16 MiB 反向讀與 256 KiB RET sled；4 次約 129 MiB（只算讀是 64 MiB）。迴圈內必須餵 watchdog，否則會吃掉 30 秒的階段預算（`:5608-5611`）。

**`sys_call_table` 是活的分派表。** 被改的格子任何行程都可能呼叫；安裝、使用、還原必須在同一次命令內完成（`:727-729`、`:600-604`）。

**兩個 stub 必須用不同的 syscall 號。** 同號會讓後安裝的 target 覆蓋前一個：一次實作中「讀取」因此變成「寫入」，把 `0xCC` 寫進 `rsc_drv` 的 `base`／`tcs_base`（`:848-849`、`:928-930`）。

**安裝 stub 的三道閘。** 進入點 PA 在窗內、stub PA 在窗內、`|target − (stub+12)| ≤ 2^27`（imm26×4 的上界）。距離閘同時是「target 不會逃出核心 text」的保證；`target_va` 本身沒有 VA 守門（`:326-329`）。

**KREAD 與 KWRITE 的介面。** `__arch_copy_to_user` 對來源不做 fault 處理，VA 0 或非核心位址會直接在核心態觸頁錯誤（`:353-354`）；KREAD 先把目的緩衝填成 `0xCC`，未讀到的尾巴會顯示為 `cc`（`:352`）。`copy_from_user` 的參數順序與 `copy_to_user` 相反：KWRITE 的 `to` 是核心目標 VA，`from` 是使用者來源緩衝（`:422-423`）。KREAD 的 `n` 下限 64（小於 1 時重設）、上限 65,536，目的緩衝同尺寸（`:348-351`）；KWRITE 的緩衝 4,096 bytes，超過的部分不解析（`:411-421`）。兩者都先檢查 VA 的高 24 位是 `0xffffff`（`:356`、`:426`）。

**為什麼改 text 而不是改頁表。** 3 GiB 物理窗到不了核心頁表：描述這個窗的頁表本身在窗外（`:273-274`）。位址算術 `PA = (VA − δ) − 0xffffffc010000000 + 0xa0000000` 與 `KNOWN_IMG + (link − ST_TEXT_LINK)` 等價；若改用 `PA_OF` 的 `IMAGE_PA = 0x90080000`，會得到 `0x90316278`，這個位址仍在 3 GiB 窗內，窗檢查攔不到，於是靜默讀寫偏移 256 MiB 的實體頁（`:5487-5491`、`:5442-5445`）。

**fail-closed 的錯靶閘。** 寫入前必須讀回 stub 仍是 `0x928004a0`／`0xd65f03c0`（`mov x0,#-ENOSYS; ret`）；不符就跳過 patch，阻止 payload 寫進任意核心 text（`:5516-5519`、`:5479-5483`）。payload 形狀是 `adrp`＋`add`＋`b`（`:5431-5435`），沒有 `bl`（`x30` 保持 syscall 進入時的返回位址）、沒有 load/store、沒有 stack、沒有 pkey 配置（`:5465-5467`）；`b` 的 imm26 是 `(target − (pc0+8)) >> 2`（`:5507`）。

### 4.3 MMIO 與 SMMU teardown

**Device 記憶體不能用一般存取器，且介面只接受 32-bit。** `copy_to_user` 對 Device 記憶體會 fault；MMIO 必須走 `__memcpy_fromio`／`ioread32`／`iowrite32`（`kgsl_23373_poc.c:455-456`、`:479-480`、`:502-506`）；介面只接受 32-bit（`:931`）。判別實驗因此不走 `__memcpy_fromio`，而用 `copy_to_user` 讀 4 bytes（`:1004-1015`）。

**不要讀 RSC TCS 的中斷暫存器。** `IRQ_ENABLE(0x00)`／`IRQ_STATUS(0x04)`／`IRQ_CLEAR(0x08)` 是 read-clear 語意；讀了會清掉 RPMh 的完成中斷，驅動會卡死。可讀的是 `CMD_WAIT_FOR_CMPL(0x10)`、`CONTROL(0x14)`、`STATUS(0x18)`、`CMD_ENABLE(0x1C)`、`CMD_MSGID(0x30)`（`:675-678`）。

**高頻 MMIO 讀會讓裝置停滯。** 0.25 秒一次的節奏會造成停滯；取證迴圈改用 1 秒（`:1182-1183`）。對照實驗用同樣的迴圈與 fsync 節奏但只讀 DRAM 欄位（`rsc_drv` 與 IPC log），分離毒源（`:1305-1308`、`:1347-1370`）。

**命令前綴的陷阱。** 分派用 `strstr`，且 `MMIOR` 排在 `MMIOR2` 之前；送 `"MMIOR2 ..."` 也會命中 `MMIOR`，參數從 `"2 ..."` 起解析，多打一次非預期的 `syscall(2, …)` 並印一行假的 `[MMIOR]`（`:457-459`）。`MMIOR2` 的 `n` 小於 1 或大於 256 時直接重設成 4，沒有夾邊；兩個 syscall 的回傳值不檢查，失敗時 `val=` 全是 `0xCC` 預填值（`:566-567`）。

**最後一個 kgsl fd 關閉就是 teardown。** `kgsl_release` → pagetable 銷毀（`kgsl_iommu.c:894-900`）→ `iommu_domain_free` → `arm_smmu_destroy_domain_context`（`arm-smmu.c:2339`）→ 對 65,539 條 dangling PTE 走頁表拆解。序列是：結束同族行程 → server 退場 → `f_count→0` → teardown → 凍結。

**凍結點的機制。** 凍結點落在 `__arm_smmu_tlb_sync` 的 TLBSYNC 輪詢；`arm-smmu.c:68` 的編譯期常數 `TLB_LOOP_TIMEOUT` 是 500 ms，`__arm_smmu_tlb_sync` 以 `udelay` 指數退避忙等（`arm-smmu.c:792-801`）。`[未重新量測]`

**設計後果：保留一個 fd 持有者。** release 命令與主行程的 `uaf_pause()` 都刻意不讓 `f_count` 歸零（`kgsl_23373_poc.c:3589-3593`、`:192-198`）。clone 出的子行程共用同一個 kgsl fd，`f_count` 要等所有持有者離開才會歸零；release 命令因此先殺掉其他 kgsl 子行程（uid 0 的也算），再讓 server 成為最後持有者（`:3589-3640`）。

**退出、release 與 free 的順序。** 快速 release 的死亡點在 kill 階段，不在 teardown；先完成 free 段再退出的序列可以存活。測試 teardown 走「先 release（存活）→ 再 exit」，不需要重啟（`:3589-3593`）；未 heal 的 UAF 物件在 teardown 時即卡死。free 在 GPU 活躍時不穩，先停心跳讓 GPU 進 slumber（`:3589-3640`）。有界化的 TLBSYNC 實驗把 `arm_smmu_tlb_inv_context_s1` 改成 `ret`、`__arm_smmu_tlb_sync` 改成 `mov w0,#0; ret`，拆掉 500 ms 輪詢；這是診斷設定，不是出貨設定（`:1408-1412`）。

### 4.4 回收、噴射與唯讀掃描

**churn 必須在競態之後。** 競態前的 8 MB 配置會讓 transient 插入每次錯過，並吃掉競態依賴的 freed frame——pool 先發最近釋放的塊。改成競態完成後、free(A) 前才配置（`kgsl_23373_poc.c:4620-4623`）。

**preburn／burn 會吃掉 freed pages。** UAF 後約 115K 頁的 burn 會把 freed frame 從 pool 頂端吃掉，`kmalloc-256` slab 就碰不到它（`:4740-4743`）。buddy freelist 頭插、`rmqueue` 取頭，所以最後釋放的 chunk 最先被偷；排水時以 `pr[n_pr−1]→pr[0]` 釋放，讓最靠近原始頭部的塊最後釋放、優先被 UNMOVABLE fallback 偷走，這是偏置，不是保證（`:4784-4788`）。

**P1 的長 hold 被跳過。** 本裝置的 kgsl pool 不會被排空，UAF 約 30 秒內觸發，長 hold 會超過它的壽命；程式碼跳過 P1（`:4798-4800`），保留 2.6 的排水（`:4758-4795`）與 UNMOVABLE 壓力（`:4909-5009`）後進噴射（`:5011`）。噴射的中止條件是 4 KB 物件配置延遲的 EMA：樣本滿 8 且 EMA 值超過 15 ms 就停泊，避免 rbtree 過大拖垮掃描（`:5046-5052`）；掃描命中即停止（`:5036`）。

**UNMOVABLE 原語。** pipe `F_SETPIPE_SZ` 1 MiB ×600（pipe 頁是 order-0 UNMOVABLE）（`:4922-4923`）、socketpair `SO_SNDBUF` ×4000 非阻塞填隊（skb 是 UNMOVABLE）（`:4945-4948`）、短 dgram 爆發燒 per-CPU 存貨（`:4972-4973`）。fork 加 mmap anon 只產生 MOVABLE 壓力，對驅動 fallback 無效（`:7864-7865`）。

**哨兵只存在於 legacy 對照。** 主路徑不寫哨兵：masquerade 寫入會覆蓋窗（`:4746-4751`）。唯一寫入是 `legacy_blind_write()`（`:3382`），由 `LEGACY_BLIND_WRITE` 或 `BLIND_WRITE_AFTER_ROOT` 開啟，呼叫端傳全窗 65,539 頁（`:5084`、`:5742`）。

**交錯 groom 與 L3 預熱（`mode_oob`）。** `mode_oob` 路徑每 16 個 spray entry 夾一個 64 KB groom BMO，讓它的 `pages[]`（`kmalloc-128`）散佈在 victim 陣列附近（`:5059`）；噴射前另有 256 個 64 KB BMO 的密集 groom（`:4898`）。L3 預熱（無條件）是 200 個 dummy BMO 的 alloc+free，不消耗 freed 頁（`:4882-4883`）。

**parked 子行程。** 每個預留 16 KB 棧區、不用 `MAP_POPULATE`；`PARK_MAX × 16 KB` = 18.75 MiB 位址空間（`PARK_MAX` = 1200，出貨用 800），常駐只有每疊頂端一兩頁。用途是各持一份私有 cred、逼 `cred_jar` 長出新 slab 頁，父行程再取最新槽（`:2303-2305`、`:5137-5142`）。出貨快路徑跳過它們，同一個 binary、一個旗標切換的乾淨單變因 A/B 顯示成功率沒有改變。成本是 800 個常駐行程與持續喚醒負載，且 `park_release()` 殺不掉它們：clone 繼承自己的 write end，子行程又把 TERM/HUP 設成 ignore，只有 SIGKILL 有效（`:5154-5160`）。

**盲寫的代價。** 舊做法在窗內每個候選 slot 的 `+0x30` 寫哨兵，再用 `INFO` 讀回 size；每輪約 62 萬次盲寫，其中 99.4–99.75% 落在別的程序頁面。改用唯讀掃描後，沒有 GPU 寫入，就沒有 marker 家族可被破壞（`:3224-3230`）。

**判據。** 改讀 `entry+0x20` 的 `memdesc.gpuaddr` 與 `+0x98` 的 `entry.id`。只用 `gpuaddr` 不夠：`KGSL_IOMMU_VA_BASE64` 是每個 pagetable 共用的 `va_start`，配置器是 per-pagetable lowest-first，別的 kgsl client 的 `gpuaddr` 可能落在同一個 band；`size`／`flags` 對 4 KB BMO 沒有鑑別力（`size` 是 `0x1000`、`flags` 是 `0xc0000`）。要求 `gpuaddr` 與 `id` 同時吻合同一 entry，碰撞機率可忽略（`:3245-3252`）。

**幾何。** 每批 256 頁 ×8 槽；每槽讀 3 個 dword（`gpuaddr` lo/hi、`id`），三個 `CP_MEM_TO_MEM` 封包共 18 words，36,864 words/批約 144 KiB，低於 512 KiB 的 IB 上限；目的緩衝 2,048 槽 ×16 B = 32 KB，低於 64 KB（`:3232`、`:3281-3296`）。

**retire 同步是必要的。** 沒有同步點時，同一輪的兩次掃描結果會不同；有同步點時才一致。解碼槽的 nonzero 比例會從個位數百分比升到數十個百分比（`:3234-3238`）。這個函式每輪跑 256 個以上的 batch，曾懷疑它造成 RSC 交易堆積（`:3323-3327`）。

**批次砍半與候選順序。** fault 時把 batch 砍半並重試同一範圍；唯讀掃描的重試零成本、零污染，不跳批就沒有覆蓋損失（`:3260-3261`、`:3309-3318`）。取 8 個候選、newest-first；`hit_pages` 依掃描遞增順序記錄，`nr−1` 是最晚被掃到的，而掃描之後、驗證之前鏈自己會往要讀的記憶體配置約 3.5 MB（credential churn 加 burn waves），越舊的候選越可能被零頁蓋掉。兩個通道都回報成功但一致回 0 時，代表該頁真的是零（`:5210-5217`）。這個迴圈原本沒有更新 round，8 個候選可能超過 30 秒的階段上限而被 watchdog 停泊（`:5226-5229`）。

**legacy 對照的模式。** 重跑舊的全窗盲寫可以隔離「污染」這個單一變因，但必須在 root 確認之後才污染窗；在掃描之前污染會讓對照組連 root 都拿不到（`:3375-3381`）。

### 4.5 位址推導與控制平面

**δ 的來源與拒絕條件。** 從 `gpu_read_memdesc` 讀回的 `ops` 推導 KASLR slide：`ops` 必須來自同一個被辨識的槽；高 32 位必須是 `0xffffffc0`（VA_BITS=39）；slide 必須 2 MB 對齊；任一不符就回 `-1`，不退回靜態符號（`kgsl_23373_poc.c:3089-3092`）。δ 每開機不同，掃描因此用通用特徵：top 16 bits 為 `0xffff`、low 12 bits 等於 `kgsl_pool_ops`、且不是填充圖樣（`:5314-5321`）。

**ImagePA 用固定載入址探測。** bootloader 把 image 固定載入 `0xa0080000`；直接探測該 PA 並驗證 ARM64 header，比 top-down 全窗掃描快，因為後者常在掃到 image 錨點前就被 harness watchdog 殺掉（`:5781-5784`、`:5793-5797`、`:6246-6252`）。header gate 的欄位：`code0` = `0x91005A4D`、`e_phoff` = `0x40`、`text_offset` = `0x80000`、image 大小 16–128 MiB、G-KV 恆等式 `kvoff == (link+δ) − ImagePA`、`physvirt_offset` 與 M 自洽、M 1 GB 對齊；任一不符即棄用該 ImagePA（`:5810-5816`）。

**雙重位移與 PT 指紋。** ARM64 Image header 內嵌於 `_text`，所以 `_text` 的 PA 等於 image 基址；不要再加一次 `TEXT_OFFSET`，載入器已經套用過 `0x80000`（`:6268-6270`）。victim 的 level-3 表項是 `attrs|PFN`，PFN 從 `0x80000` 起連續遞增；20 位元序列匹配的誤陽趨近零，命中即得 `PA_pt`，單一方程解 M（`:6022-6025`）。

**swapper 錨點與 task_struct 偏移。** `init_task` 的 comm 是 `"swap"`、`"per/"`、`"0\0\0\0"`；第三個字是 `0x00000030`，不是 `0x0000302F`（後者多算了一個 `/`），舊常數因此無法匹配（`:6038-6039`）。本 kernel 的 `pid_type` 含 `PIDTYPE_TGID`，`pid_links[4]` 是 64 B；用 pre-5.3 三項佈局的常數會少 16 B，候選落在真 `task_struct` 之前，`tasks.next` 讀到錯位垃圾（`:5371-5375`）。

**`getuid()` 只證明 subjective cred。** `current_cred()` 是 `current->cred`，`override_creds()` 只換 `cred` 就讓 `getuid()` 回 0；需要 `real_cred` 的檢查仍看到原身分。直接改 `task_struct` 的路徑同時換兩個指標（`:7199-7201`）。

**鏈走訪的誤陽。** 單向 8 步走訪有約 43% 機率接受錯的 k；現行路徑要求 6 步，且每個鄰居的 comm 首 byte 必須可列印（`:7369-7372`、`:7411`、`:7418`）。

**指標交換與 fsuid 陷阱。** 內容補丁的 cred 會在窗頁被回收時消失；`init_cred` 是 `.data` 的靜態物件，對頁面回收免疫。對主行程交換兩個指標後以 `getuid()==0` 即驗即收；對子行程交換後廣播 ack（`:6729-6732`）。把 uid／gid／suid／sgid／euid／egid 設成 0、但保留 fsuid／fsgid = 2000，`getuid()==0` 仍會在建立檔案時走 owner bits 而被 DAC 拒絕；沒有 AVC 表示這是純 DAC 拒絕（`:6606-6609`）。出貨路徑把 SELinux 設成 permissive，讓 `CAP_DAC_OVERRIDE` 生效（`:6839-6842`）。

**selinux_state 佈局與毒化防護。** 5.4 的 `struct selinux_state` 是 `bool disabled@0`、`bool enforcing@1`；讀 `+0` 得到 `0x1000000`，`+1` 才是 enforcing byte（`:6849-6850`）。補過的 cred 要記錄；無論是否拿到 root，都把非勝出者的 uid 欄還原成 2000（勝出者保留 uid 0），留下被補丁的非 shell 系統 cred 會讓裝置崩潰（`:6641-6650`、`:6706-6727`）。

**頂段是偽簽名區。** `off ≥ 0xA0000000`（PA ≥ `0x120000000`）是 secure-watchdog 的偽簽名區；真樣本都在低段（`:6103-6106`）。程式碼另記錄 PA 約 5 GB 以上是即死區，實際邊界沒有重新量測（`:5944-5946`）。`[未重新量測]`

**M 求解的五級順序。** image 錨點 → k 枚舉（421×14，需 6 步）→ 鄰接投票（至少 3 票）→ cred VA 交集（至少 4 個貢獻候選、score ≥ 3）→ 六值暴力（score ≥ 3）；全敗則跳過該候選（`:7354-7358`、`:7418-7420`、`:7422-7426`、`:7497-7500`）。

**命令檔會重播，且沒有分幀。** 命令檔是 `/data/local/tmp` 下的普通檔，跨重啟存活；首次開啟若從 offset 0 讀，會把上一輪的命令整份重播。`RELEASE_MAIN` 重播會讓新鏈立即退場（`:4251-4253`）。修法：首開直接 seek 到 EOF（`:223-227`、`:4254-4257`）。pause 讀取器的緩衝是 127 bytes、沒有分隔符分幀，超長命令（KWRITE／KRFWD）會被切斷，尾巴下一輪當新命令解析且不報錯（`:225-226`）；主迴圈的緩衝是 256 bytes（`:4250`），同樣沒有分幀。

**停泊的語意。** UAF 建立後，退出或被殺會觸發 kgsl teardown；所有失敗路徑都進 `uaf_pause()`，TERM／INT／HUP 也改成 pause（`:202-208`、`:1486`）。出口只有控制命令（`:8510-8512`）。

**watchdog 與接手。** 階段預算 30 秒；watchdog 在 main 卡住時接手 root 收尾，並 fork 出 server（`:4295-4302`）。fork 子行程繼承呼叫執行緒的 cred，watchdog 執行緒的 uid 仍是 2000，所以它 fork 出的 server 只能當中繼探針（`:4323-4325`）。

**保活子與 raw clone。** 一個常駐 `sh` 迴圈每秒輪詢 `/data/local/tmp/rootcmd2`，有內容就執行並把輸出寫到 `rootout2`；它在 server 靜默死亡後仍存活，`execve` 後映像與 TLS 全新，不受 raw-TLS 缺陷影響（`:2158-2174`）。`TPIDR_EL0=0` 時 glibc `syscall()` 的 errno 路徑會 deref TLS 而 SIGSEGV，因此走 inline asm `svc`，核心回 `-errno`，不碰 TLS（`:1628-1629`、`:2111-2113`）。子行程要重置繼承的訊號處置：parent 的 SIGSEGV handler 在 `jmp_armed` 時會 `siglongjmp` 回 parent 的棧，而 `jmp_armed`／`jmpbuf` 是 `CLONE_VM` 共享全域（`:2124-2126`）。

---

## 5. 未解問題

1. **`.337` 源碼不在專案內。** 只有 `.296` 源碼；`kernel.elf` 不隨 repo 發佈，取自裝置的 boot image。執行中的 kernel 被假定為 vulnerable，因為鏈在它上面成功，且 `kernel.elf` 的四個 hunk 都不存在。`kernel.elf` 與 flashed image 的逐位元組一致性沒有 device-side hash 或 build id，只以 banner、符號與反組譯比對推定。`[推論]`
2. **修補的因果沒有受控實驗。** 沒有 fixed-kernel 的 A/B，也沒有只關閉單一 CVE 的 A/B；現有證據是源碼、兩個 runtime WARN、`unmapped = 0` 與 65,539 頁幾何。
3. **重建後的別名共享。** `rebuild_ctx()` 把 IB 三個欄位整組指向 `spare_g` 的 pre-UAF IB；此後 `g` 與 `spare_g` 別名同一個 gpuobj id 與同一個 mmap。任何一方呼叫 `gpuobj_free()` 都是對對方仍在用的物件下手；目前沒有這樣的呼叫（`:2773-2777`）。
4. **`GPUOBJ_INFO` 不驗證 size。** 這個 ioctl 直接回報 `memdesc.size`，是 size 讀回可以當 oracle 的原因（`kgsl.c:3743-3761`）。
5. **1 GiB mmap 的排序。** 只在 ops 落地後才做 1 GiB mmap；ops 與 `+0x2c` 合批寫有死亡記錄，因此前 4 輪只寫 `ops`、之後才加 `+0x2c`；ops 階段前的 8 次 1 GiB mmap+munmap 曾讓裝置重啟；存活邊界是第二輪，不是第四輪（`:7683-7686`、`:7735-7737`）。
6. **任意物理讀的證明。** 讀到 `0x91005a4d`（本機 kernel image 開頭的 u32）才算成立；mmap 成功或 `ERANGE` 只是候選訊號（`:7762-7763`、`:8346-8348`）。
7. **oobprobe 是二元事件。** 觸碰 `pages[1]`（VA+0x1000）時，`PANIC_ON_OOPS` 下不是成功就是重啟；它要求 `size` 已由 bigmmap 模式寫成 1 GiB（`:7807-7813`）。
8. **bulk `CP_MEMCPY` 與單 dword 的差異。** stale mapping 可能允許 `CP_MEM_WRITE` 但讓 bulk `CP_MEMCPY` fault；逐 dword 探測才能區分讀權限 fault 與封包／緩衝問題（`:7630-7632`）。
9. **`pages@+0x68` 的指標。** 由 `PHYS_ADDR` 算出的指標低 32 位高 `0x200000`（高 32 位 `0xffffffc0` 正確）；readback 不含 `pages`，錯值不會被驗證步驟抓到（`:8244-8247`）。
10. **sigsetjmp 的共享狀態。** 全檔 62 個 `sigsetjmp` 呼叫點；60 個共用 `jmp_armed`／`jmpbuf`，另兩個分別用 `jmpbuf2`（`:5586`）與 `jmpbuf3`（`:5656`）。deref 守衛依賴第一組（`:8370`）。
11. **某些段落沒有成功判定。** verdict 在子行程：輪詢 uid==0 → 寫 proof → 進 root fifo server。root 時 server 不返回，`waitpid` 永久阻塞；「children 結束」與 `done` 只在失敗路徑出現（`:8474-8479`、`:8509`）。
