# 三個 KGSL／IOMMU 缺陷

**行號基準**：`poc/kgsl_23373_poc.c`（8515 行）；裝置源碼樹為 ASUS `33.0210.0210.296` 的 `kernel/msm-5.4`（`Makefile` 的 `SUBLEVEL = 147`）。上游檔案行號以實際抓取的 commit／branch 為準，引用處逐一標明；`.337` 源碼不可取得，行號以 `.296` 為基準。

## 摘要

**CVE-2023-33107** 讓 SVM 範圍檢查接受回繞後的 `gpuaddr + size`，重疊映射因此繞過 rbtree；**CVE-2024-21468** 讓失敗映射的回滾多清一個既有 PTE，打出 4 KB 的洞；**CVE-2024-23373** 讓 unmap 失敗後仍釋放 backing pages，留下 65,539 個懸空 SMMU PTE。三者在 `5.4.210-qgki-perf-g6e91db764350` 上同時存在，任一缺陷的修補都能獨立斷鏈。

## 1. 影響範圍

### 1.1 受影響的程式碼

| 元件 | 檔案 | 缺陷 |
|---|---|---|
| KGSL SVM 位址管理 | `drivers/gpu/msm/kgsl_iommu.c` | `iommu_addr_in_svm_ranges()` 缺少回繞檢查（33107） |
| arm LPAE 頁表層 | `drivers/iommu/io-pgtable-arm.c` | `arm_lpae_map_sg()` 快速路徑丟棄 `arm_lpae_init_pte()` 的回傳值（21468） |
| KGSL MMU 釋放路徑 | `drivers/gpu/msm/kgsl_mmu.c`、`kgsl_sharedmem.c`、`kgsl.c` | unmap 錯誤被吞、free op 不檢查 `MAPPED`（23373） |

### 1.2 受影響的核心版本

判斷標準是三個函式是否仍保持缺陷形態，不是版本號：`iommu_addr_in_svm_ranges()` 沒有 `end <= gpuaddr`；`arm_lpae_map_sg()` 的 map-state 快速路徑沒有檢查 `arm_lpae_init_pte()` 的回傳值；`kgsl_mmu_unmap()` 在 `mmu_unmap()` 失敗後仍清除 `MAPPED`，且 free op 沒有 `MAPPED` 守衛。對應修補分別在 2023-12、2024-04、2024-07 的公告中發布；vendor 分支若在 backport 之前凍結且未另行合入，建置日期不提供保護。受影響面不限於手機：Qualcomm msm-5.4 KGSL 與 arm-smmu／io-pgtable-arm 是 SoC 廠共用元件；其他沿用同一分支的 Android 或嵌入式裝置，要用同樣的三條函式形態逐一判斷。

### 1.3 目標裝置

| 項目 | 值 |
|---|---|
| 裝置 | ASUS Zenfone 8 Flip（ASUS_I004D／ZS672KS），Snapdragon 888（SM8350），Adreno 660 |
| Android | 13，build `33.0210.0210.337` |
| Kernel | `5.4.210-qgki-perf-g6e91db764350`（Qualcomm msm-5.4） |
| 可取得的源碼 | ASUS `33.0210.0210.296`，`Makefile`：`VERSION 5`／`PATCHLEVEL 4`／`SUBLEVEL 147` |
| 執行映像（分析用） | 核心 ELF，banner 為 `5.4.210-qgki-perf-g6e91db764350`；建置時間 2025-12-16；不隨 repo 發佈 |
| 既有記錄的 SPL | 2023-11-01（未獨立重驗） |

### 1.4 CVE 識別資料

NVD 描述取自 `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=...`（2026-10-19 抓取）：

| CVE | NVD 描述 | CWE | CVSS 3.1 |
|---|---|---|---|
| CVE-2023-33107 | `Memory corruption in Graphics Linux while assigning shared virtual memory region during IOCTL call.` | CWE-190 | 8.4（Qualcomm）／7.8（NIST） |
| CVE-2024-21468 | `Memory corruption when there is failed unmap operation in GPU.` | CWE-416 | 8.4（Qualcomm）／7.8（NIST） |
| CVE-2024-23373 | `Memory corruption when IOMMU unmap operation fails, the DMA and anon buffers are getting released.` | CWE-416 | 8.4（Qualcomm）／7.8（NIST） |

## 2. 技術背景

`kgsl_memdesc` 的關鍵欄位是 backing memory（`pages[]`／`sgt`／`physaddr`）、`size`、`gpuaddr`、`priv`（`KGSL_MEMDESC_MAPPED` 表示物件目前在 IOMMU 頁表中）與 `ops`（含 `free`／`vmfault`）。SVM 允許使用者指定 GPU 位址；KGSL 以 rbtree 追蹤區間，節點鍵值是 base，`kgsl_mmu_set_svm_region()` 先驗範圍、再走訪 rbtree 確認無重疊、最後 `_insert_gpuaddr()`。位址翻譯用 ARM LPAE、4 KB granule、39 位元 VA，走訪從 level 1 到 level 3；level 2 可放 2 MiB block。`arm_lpae_map_sg()` 的 map state 在連續頁落在同一 2 MiB 窗口與同一張 level-3 表時走快速路徑，直接以 `arm_lpae_init_pte()` 寫 PTE。

## 3. CVE-2023-33107 — SVM 範圍檢查的 64 位元回繞

### 3.1 觸發路徑

使用者以 `IOCTL_KGSL_GPUOBJ_IMPORT`、`type = KGSL_USER_MEM_TYPE_ADDR`、`flags = KGSL_MEMFLAGS_USE_CPU_MAP` 匯入一段使用者虛擬位址，長度由 `priv_len` 指定。呼叫鏈：`kgsl_ioctl_gpuobj_import()` → `kgsl_setup_anon_useraddr()`（`kgsl.c:2547-2582`）→ `kgsl_mmu_set_svm_region()`（`kgsl_iommu.c:2185-2219`）→ `iommu_addr_in_svm_ranges()`（`:2169-2183`）→ rbtree 重疊檢查（`:2199-2213`）→ `_insert_gpuaddr()`（`:2215`）；之後 `memdesc_sg_virt()`（`kgsl.c:2488-2541`）建立 SG 表。`kgsl_setup_anon_useraddr()` 在 `memdesc_sg_virt()` 失敗時呼叫 `kgsl_mmu_put_gpuaddr()`（`kgsl.c:2578-2579`）移除區間；這條失敗路徑是競態窗口的來源。

### 3.2 缺陷機制

裝置源碼的檢查如下（`kgsl_iommu.c:2169-2183`）：

```c
if ((gpuaddr >= pt->svm_start && gpuaddr < pt->svm_end) &&
    ((gpuaddr + size) > pt->svm_start &&
     (gpuaddr + size) <= pt->svm_end))
	return true;
```

`gpuaddr` 與 `size` 都是 `u64`，加法以 modulo 2^64 計算。函式只檢查相加結果是否落在 `[svm_start, svm_end)`，沒有檢查結果是否小於 `gpuaddr`；只要 `size` 夠大，終點可以回繞到窗口內。64 位元 SVM 窗口是 `[0x100000000, 0x4000000000)`（`kgsl_iommu.h:43-44`）。PoC 使用 `BOGUS_ADDR = 0x700204000`（`:2397`）與 `BOGUS_PRIVLEN = 0xffffffffffefd000`（`:2400`，即 `2^64 - 0x103000`），相加得 `0x700101000`（mod 2^64），落在窗口內。`_insert_gpuaddr()` 以 base 為鍵插入，得到終點小於起點的區間 `[0x700204000, 0x700101000)`。

倒置區間破壞 `base < end` 不變式。重疊檢查（`:2199-2213`）以 `end = entry->base + entry->size` 走訪：`gpuaddr + size <= start` 往左子樹、`end <= gpuaddr` 往右子樹，其餘判定重疊並回傳 `-ENOMEM`。對倒置節點，`end <= gpuaddr` 對幾乎所有查詢成立，走訪因此往右子樹，不在該節點判定重疊。PoC 的插入順序（A 在 `0x7001ff000`、PLACE 錨點在 `0x710204000`、倒置節點在 `0x700204000`）使查詢 `OVER_ADDR = 0x7001fe000` 在倒置節點往右、在 PLACE 往左，最後到達 NULL 並插入，A 從未被比較（`[推論]`，見 §11.2 第 2 項）；`end <= gpuaddr` 使走訪偏離 A 是程式碼的直接結果。回繞的 import 本身不會成功：`memdesc_sg_virt()` 對這個長度呼叫 `kvcalloc()` 必定失敗，區間隨後被移除；可利用的是它在樹上存在的那段窗口，`warn_alloc` 的 `dump_stack`／`show_mem` 把窗口拉長到數毫秒。

### 3.3 上游修補

Commit `d66b799c804083ea5226cfffac6d6c4e7ad4968b`（`msm: kgsl: Prevent wrap around during user address mapping`，Qualcomm `msm-4.19`，2023-09-28；`https://git.codelinaro.org/clo/la/kernel/msm-4.19/-/commit/d66b799c804083ea5226cfffac6d6c4e7ad4968b.patch`）先把終點算一次、拒絕回繞，再用同一個 `end` 做兩段範圍比較：

```c
u64 end = gpuaddr + size;

/* Make sure size is not zero and we don't wrap around */
if (end <= gpuaddr)
	return false;
```

### 3.4 PoC 對照

幾何常數在 `:2393-2414`；`bogus_thread()`（`:2549-2577`）以 `virtaddr = BOGUS_ADDR`、`priv_len = BOGUS_PRIVLEN`（`:2556-2558`）反覆發出回繞 import；主迴圈在 `:2671-2681` 同時嘗試重疊配置與 `mmap()`，`ENODEV` 被視為「映射已進入頁表層」的訊號。

## 4. CVE-2024-21468 — 被丟棄的 `-EEXIST`

### 4.1 觸發路徑

使用者對一個 `GPUOBJ_ALLOC` 物件在指定 GPU 位址 `mmap()`；位址由 `.get_unmapped_area` 鉤子配置（`kgsl.c:4260`）。呼叫鏈：`kgsl_get_unmapped_area()`（`kgsl.c:4118`）→ `get_svm_unmapped_area()`（`:4052`）→ `set_svm_area()`（`:4029-4050`）→ `_gpu_set_svm_region()`（`:3973-4013`）→ `kgsl_mmu_set_svm_region()`（`kgsl_iommu.c:2185-2219`）→ `kgsl_mmu_map()`／`_iommu_map_sg()`（`:361-382`）→ `iommu_map_sg()`／`arm_smmu_map_sg()`（`arm-smmu.c:3362-3460`）→ `arm_lpae_map_sg()`（`io-pgtable-arm.c:612-695`）。

`_gpu_set_svm_region()` 在 `kgsl_mmu_set_svm_region()` 成功後設定 `memdesc.gpuaddr`，再呼叫 `kgsl_mmu_map()`（`kgsl.c:3990-4003`）；map 失敗時呼叫 `kgsl_mmu_put_gpuaddr()` 清理（`:4004-4006`）。

### 4.2 缺陷機制

`arm_lpae_init_pte()` 在 PTE 已有效時 `WARN_RATELIMIT(1, "map without unmap\n")` 並回傳 `-EEXIST`（`io-pgtable-arm.c:376-388`）。快速路徑（`:655-662`）呼叫它但不接收回傳值，慢速路徑則會檢查：

```c
if (ms.pgtable && (iova < ms.iova_end)) {
	arm_lpae_init_pte(data, iova, phys, prot, MAP_STATE_LVL,
			  ptep, ms.prev_pgtable, false);
	ms.num_pte++;
} else {
	ret = __arm_lpae_map(data, iova, phys, pgsize, prot, lvl, ptep, NULL, &ms);
	if (ret)
		goto out_err;
}
```

快速路徑的錯誤被丟棄後，`ms.num_pte++` 與外層的 `mapped += pgsize` 照常執行，這個「其實沒有寫入」的頁面被計入已映射長度。

PoC 的重疊映射是 7 頁、起點 `HOSTPTR - 0x1000`（`:2401`、`:2404`），包含一個前綴頁與 A 的前六頁。第 0 頁 `0x7001fe000` 是新的，成功寫入 PTE，`__arm_lpae_map()` 設定 `ms.iova_end = round_down(iova, SZ_2M) + SZ_2M = 0x700200000`，並把該 level-3 表的計數加一。第 1 頁 `0x7001ff000`（`HOSTPTR`）落在同一個 2 MiB 窗口，走快速路徑；PTE 已由 A 建立，`arm_lpae_init_pte()` 回傳 `-EEXIST` 但被丟棄，`mapped` 變成 `0x2000`。第 2 頁 `0x700200000` 不再小於 `ms.iova_end`，走慢速路徑；`__arm_lpae_map()` 在 A 的下一張 level-3 表看到有效 PTE，回傳 `-EEXIST`，`out_err` 把 `*size = mapped = 0x2000` 寫回（`:691-694`）。

`arm_smmu_map_sg()` 看到負回傳值後，以已計入的長度計算回滾範圍（`arm-smmu.c:3437-3439`）：

```c
if (ret < 0) {
	size_to_unmap = iova + size - __saved_iova_start;
	goto out;
}
```

`out` 呼叫 `arm_smmu_unmap(__saved_iova_start, size_to_unmap, NULL)`（`:3455-3457`）。以 PoC 為例，回滾範圍是 `[0x7001fe000, 0x700200000)`，共 2 頁：第 0 頁是這次真正寫入的 PTE，清除正確；第 1 頁是 A 的既有 PTE，這次映射從未寫入，卻被一併清除。

level-3 表的計數決定損害範圍。A 的第一頁最初映射時使該表計數成為 1；重疊映射第 0 頁使其成為 2；第 1 頁在 `-EEXIST` 處提前返回，沒有再加一。回滾清除兩頁把計數減到 0，`__arm_lpae_unmap()` 因此清除 level-2 入口並釋放整張 level-3 表（**`[推論]`**：前提是該 2 MiB block 內沒有其他映射，計數才會剛好是 2）。結果是 A 在 `HOSTPTR` 的第一個 PTE 消失、該 2 MiB 窗口的 level-2 入口變成 0，其餘 65,539 個 PTE 不受影響。這個「level-2 入口為 0」在下一步才顯現：A 的 unmap 從 level 1 走到 level 2 時讀到 0，`WARN_ON(!pte)` 直接回傳 0（`io-pgtable-arm.c:813`），`arm_lpae_unmap()` 以 `unmapped = 0` 結束（`:905-906`），這就是 23373 所需的「unmap 失敗」。

### 4.3 上游修補

Commit `8376c8700f5badce175f897b2cb18a513278d703`（`iommu: Fix missing return check of arm_lpae_init_pte`，Qualcomm `msm-4.4`，2023-09-25；5.15 對應 `3cbca5d2eeec99c8e0c6f8621dd62337323ae850`，套用於 `qcom-io-pgtable-arm.c` 的 `arm_lpae_map_by_pgsize()`）讓快速路徑與慢速路徑一致：

```c
ret = arm_lpae_init_pte(data, iova, phys, prot, MAP_STATE_LVL,
			ptep, ms.prev_pgtable, false);
if (ret)
	goto out_err;
ms.num_pte++;
```

commit message 描述的後果是：PTE 即使已存在也被計入，失敗的 unmap 之後留下指向已釋放物件的 dangling IOMMU PTE，客戶端存取它就構成 UAF。快速路徑是 vendor 在 LPAE 更新中加入的批次映射優化，mainline 沒有這個設計；修補的 `Fixes:` 指向 `27de1978c331`（`ANDROID: GKI: iommu/io-pgtable-arm: LPAE related updates by vendor`）。優化加入時漏掉慢速路徑已有的回傳值檢查，之後的 vendor 分支沿用同一形態。

### 4.4 PoC 對照

`OVER_ADDR = HOSTPTR - 0x1000`、`OVER_SIZE = 0x7000`（`:2401`、`:2404`）；重疊物件在 `:2673-2677` 配置並嘗試 `mmap()`，`:2678` 的 `errno == ENODEV` 被視為「映射已到達頁表層並失敗」的訊號。

## 5. CVE-2024-23373 — unmap 失敗後仍釋放 backing pages

### 5.1 觸發路徑

使用者以 `IOCTL_KGSL_GPUOBJ_FREE` 釋放物件 A（`:2696`）。呼叫鏈：`kgsl_ioctl_gpuobj_free()` → `gpumem_free_entry()`／`kgsl_mem_entry_destroy()` → `kgsl_sharedmem_free()`（`kgsl_sharedmem.c:699-712`）→ `kgsl_mmu_put_gpuaddr()`（`kgsl_mmu.c:392-422`）→ `kgsl_mmu_unmap()`（`:441-474`）→ `kgsl_iommu_unmap()`／`_iommu_unmap()`（`kgsl_iommu.c:339-359`）→ `iommu_unmap()`／`arm_smmu_unmap()`／`arm_lpae_unmap()`；之後 `memdesc->ops->free()`（`kgsl_sharedmem.c:711`）。

### 5.2 缺陷機制

第一步是 unmap 回報的錯誤被吞掉。`_iommu_unmap()` 在實際清除長度不等於請求長度時回傳 `-ENODEV`（`kgsl_iommu.c:352-356`），`kgsl_mmu_unmap()` 收到錯誤後仍無條件更新統計並清除 `KGSL_MEMDESC_MAPPED`（`kgsl_mmu.c:460-470`）：

```c
unmapped = iommu_unmap(iommu_pt->domain, addr, size);
if (unmapped != size) {
	dev_err(device->dev, "unmap err: 0x%016llx, 0x%llx, %zd\n",
		addr, size, unmapped);
	return -ENODEV;
}
...
ret = pagetable->pt_ops->mmu_unmap(pagetable, memdesc);

atomic_dec(&pagetable->stats.entries);
atomic_long_sub(size, &pagetable->stats.mapped);
kgsl_mmu_trace_gpu_mem_pagetable(pagetable);

if (!kgsl_memdesc_is_global(memdesc)) {
	memdesc->priv &= ~KGSL_MEMDESC_MAPPED;
	if (!(memdesc->flags & KGSL_MEMFLAGS_USERMEM_ION))
		kgsl_trace_gpu_mem_total(device, -(size));
}
```

第二步是位址區間沒有被歸還。`kgsl_mmu_put_gpuaddr()` 只在 `unmap_fail == 0` 時呼叫 `put_gpuaddr()`（`kgsl_mmu.c:400-409`）：

```c
if (!kgsl_memdesc_is_global(memdesc) && (KGSL_MEMDESC_MAPPED & memdesc->priv))
	unmap_fail = kgsl_mmu_unmap(pagetable, memdesc);

if (PT_OP_VALID(pagetable, put_gpuaddr) && (unmap_fail == 0))
	pagetable->pt_ops->put_gpuaddr(memdesc);
```

unmap 失敗時，A 的 SVM 區間仍留在 rbtree，而 `memdesc->gpuaddr` 在 `:419-420` 被歸零。註解說這是為了避免未來映射覆蓋既有 mapping；代價是區間與 backing 的生命週期脫鉤。修補後這個未歸還的區間只剩資源洩漏：SVM 位址與 backing pages 都不會被回收，但不再是 UAF。

第三步是 free op 沒有檢查 `MAPPED`。`kgsl_sharedmem_free()` 忽略 unmap 錯誤，直接呼叫 `memdesc->ops->free()`（`kgsl_sharedmem.c:699-712`）：

```c
void kgsl_sharedmem_free(struct kgsl_memdesc *memdesc)
{
	if (!memdesc || !memdesc->size)
		return;
	kgsl_mmu_put_gpuaddr(memdesc);
	if (!memdesc->ops || !memdesc->ops->free)
		return;
	memdesc->ops->free(memdesc);
}
```

物件 A 由 `IOCTL_KGSL_GPUOBJ_ALLOC` 配置（`:2612`），走 `gpumem_alloc_entry()`（`kgsl.c:3524`）→ `kgsl_allocate_user(..., priv = 0)`（`kgsl.c:3579-3580`）→ `kgsl_alloc_pages()`（`kgsl_sharedmem.c:1182`）。`priv = 0` 使它取得 `kgsl_pool_ops`（`:1200`），其 `free` 是 `kgsl_free_pool_pages()`（`:1056`）。這個函式沒有 `MAPPED` 守衛（`:1001-1015`），會把 A 的 65,540 個 pages 全部還給 KGSL pool（pool 滿時回到 buddy），而 `DANGLING_BASE = HOSTPTR + 0x1000` 起的 65,539 個 PTE 仍指向這些 pages。

### 5.3 修補需要兩層

ASB 2024-07-01 為 23373 列出的兩個 commit（`54aa44db`、`fd6b05db`）只在 `kgsl_destroy_ion()`／`kgsl_destroy_anon()` 加上 `MAPPED` 守衛。物件 A 是 pool 物件，free op 是 `kgsl_free_pool_pages()`；只套用 ASB 列的兩個 commit 不會阻擋這條路徑。擋住 A 的是 companion 修補 `330843f5`／`7eef6345`（5.4）與 `4ac1a9e2`（AOSP 4.19）：`kgsl_mmu_unmap()` 的提早返回，加上所有 free op 的 `MAPPED` 守衛（5.4 是 `kgsl_sharedmem.c:1020-1021` 的 `kgsl_free_pool_pages()`；AOSP 4.19 是 `kgsl_page_alloc_free()`／`kgsl_cma_coherent_free()`，`:577-578`／`:680-681`）。提早返回使 `MAPPED` 保持置位、統計不變（AOSP 4.19 `kgsl_mmu.c:493-495`）：

```c
ret = pagetable->pt_ops->mmu_unmap(pagetable, memdesc);
if (ret)
	return ret;
```

`kgsl_mmu_put_gpuaddr()` 因 `unmap_fail != 0` 跳過 `put_gpuaddr()`；`kgsl_sharedmem_free()` 走到 free op 時，`MAPPED` 守衛直接返回，backing pages 保留。完整 commit 清單見 §10.1。

### 5.4 PoC 對照

A 以 `GPUOBJ_ALLOC(UAF_SIZE, USE_CPU_MAP)` 配置（`:2612`）、以 `gpuobj_free(uaf_id)` 釋放（`:2696`）；`:2710` 以相同 `HOSTPTR` 重 import，失敗即表示 SVM 區間仍被保留；`:2719-2721` 印出 dangling 區間 `[HOSTPTR + 0x1000, HOSTPTR + UAF_SIZE)`，共 65,539 頁。判別器只看重 import 的成敗、不檢查 `errno`，判讀見 `03-limitations.md` §1.4。「只套用 ASB 2024-07-01 的兩個 commit 不足以阻擋 pool 路徑」屬源碼層推論（`[推論]`）。

## 6. 為何三個缺陷必須串連

三個缺陷是嚴格的序列依賴：前一個缺陷移除後一個缺陷的前置條件。編號是缺陷依賴的順序，對應 `02-exploit-chain.md` §2.1（第一、二環節）、§2.2（第三環節）、§2.3（第四環節）。

| 環節 | PoC 位置 | 動作 | 依賴的缺陷 | 缺少該缺陷時 |
|---|---|---|---|---|
| 1 | `:2612-2629` | 配置物件 A：`0x10004000` bytes（65,540 頁），GPU 位址固定為 `HOSTPTR = 0x7001ff000` | 無 | — |
| 2 | `:2549-2577`、`:2671-2681` | 以回繞的 `priv_len` 匯入，插入終點小於起點的 transient 區間；同時嘗試 `[HOSTPTR - 0x1000, +0x7000)` 的重疊映射 | **33107** | rbtree 偵測到 A 與請求區間重疊，回傳 `-ENOMEM`；重疊映射不會發生，21468 沒有機會執行 |
| 3 | `:2673-2677` | 重疊映射 7 頁：第 0 頁成功，第 1 頁撞上 A 的 PTE 但 `-EEXIST` 被丟棄，第 2 頁失敗；回滾清除第 0、1 頁並釋放 level-3 表 | **21468** | 第 1 頁的 `-EEXIST` 會中止映射，`mapped` 只有 `0x1000`；回滾只清第 0 頁，A 的 PTE 存活 |
| 4 | `:2696` | `FREE(A)`：unmap 在 level 2 讀到 0，回傳 0；`-ENODEV` 被吞，`MAPPED` 被清除，`put_gpuaddr()` 被跳過；pool free 釋放 65,540 頁，65,539 個 PTE 仍指向它們 | **23373** | unmap 成功後才釋放，PTE 已清除；或 unmap 失敗但 free op 有 `MAPPED` 守衛，pages 保留 |

### 6.1 21468 與 23373 位於不同階段

NVD 對兩者的描述都提到 unmap 失敗，容易誤認為同一個問題的兩種說法。實際上是不同函式、不同階段的兩個缺陷：**21468** 在 **map** 路徑，`arm_lpae_map_sg()` 丟棄 `-EEXIST`，使失敗映射的回滾範圍多算一頁，負責造洞；**23373** 在 **free** 路徑，`kgsl_mmu_unmap()` 吞掉 unmap 錯誤、free op 不檢查 `MAPPED`，負責把洞變成 UAF。

## 7. 裝置缺少的修補

### 7.1 版本與 provenance

`.296` 源碼樹是 `zenfone8_zs672ks.mp-33.0210.0210.296/kernel/msm-5.4`，`Makefile:4` 為 `SUBLEVEL = 147`。分析用的核心 ELF 是 ELF64 AArch64、`ET_EXEC`、未 strip，banner 為 `Linux version 5.4.210-qgki-perf-g6e91db764350 … #1 SMP PREEMPT Tue Dec 16 12:44:28 CST 2025`，`_text = 0xffffffc010080000`；這個檔案不隨 repo 發佈。裝置實際執行 `.337` 建置（5.4.210），`.337` 源碼不可取得；`.296`（5.4.147）與該 ELF 是兩個不同的建置，兩者都缺少這四個 hunk，結論不依賴 `.296` 等於執行中的樹。

### 7.2 四個 hunk 的源碼證據

| Hunk | 裝置 `.296` 的位置 | 缺少的內容 |
|---|---|---|
| SVM wrap 檢查 | `drivers/gpu/msm/kgsl_iommu.c:2169-2183` | 沒有 `end = gpuaddr + size`，也沒有 `end <= gpuaddr` 的拒絕 |
| `init_pte` 回傳值檢查 | `drivers/iommu/io-pgtable-arm.c:655-662` | 快速路徑呼叫 `arm_lpae_init_pte()` 但不接收回傳值，直接 `ms.num_pte++` |
| unmap 提早返回 | `drivers/gpu/msm/kgsl_mmu.c:460-470` | 保存 `ret` 後仍無條件遞減統計並清除 `MAPPED` |
| pool free 的 `MAPPED` 守衛 | `drivers/gpu/msm/kgsl_sharedmem.c:1001-1015` | `kgsl_free_pool_pages()` 直接呼叫 `kgsl_pool_free_pages()`，沒有檢查 `memdesc->priv & KGSL_MEMDESC_MAPPED` |

### 7.3 核心 ELF 的指令層證據

反組譯由 `aarch64-linux-gnu-objdump -d` 對上述核心 ELF 執行，符號位址取自同一個 ELF 的符號表。§7.2 的源碼證據不依賴這一節。

**(a) `kgsl_iommu_set_svm_region`（`0xffffffc010a34480`）：** `+0x40` 的 `add x10, x21, x20` 算出 `gpuaddr + size`，之後只有 `cmp x10, x8`／`cmp x10, x9` 兩個邊界比較與對應的 `b.ls`；沒有 `cmp x10, x20`（end vs gpuaddr）或等價拒絕分支。`x20`／`x21` 對應 `gpuaddr`／`size`、`x8`／`x9` 對應範圍邊界，是依簽章與前後指令推得（`[推論]`）；「沒有 end-vs-start 比較」本身是 `[來源]`。節錄取自 compat 檢查（`+0x28` 起），SVM 檢查（`+0x54` 起）重複同一形狀。

**(b) `arm_lpae_map_sg`（`0xffffffc01098b37c`）：快速路徑在 `-EEXIST` 後仍 `num_pte++`。**

```text
ffffffc01098b560:  f86b790a   ldr  x10, [x8, x11, lsl #3]   // load PTE
ffffffc01098b564:  3700046a   tbnz w10, #0, ...b5f0         // valid -> WARN
...
ffffffc01098b604:  350000a0   cbnz w0, ...b618              // ratelimit -> __warn_printk
ffffffc01098b608:  b94053e8   ldr  w8, [sp, #80]            // num_pte++
ffffffc01098b60c:  11000508   add  w8, w8, #1
ffffffc01098b610:  b90053e8   str  w8, [sp, #80]
ffffffc01098b4b8:  94000119   bl   __arm_lpae_map             // 慢速路徑
ffffffc01098b4c0:  35000bc0   cbnz w0, ...b638              // error -> out_err
```

`out_err` 在 `0xffffffc01098b638`，把 `*size` 設成目前已計入的 `mapped`。快速路徑的 `-EEXIST` 因此被計入 `mapped`，慢速路徑的錯誤則不會。

**(c) `kgsl_mmu_unmap`（`0xffffffc010a14220`）：** `+0x90` 的 `blr x19` 呼叫 `pt_ops->mmu_unmap()`，`+0x94` 的 `mov w19, w0` 保存回傳值，隨後 `b ...4308` 直接進統計／清除路徑；`w19` 之後只在 epilogue 被讀取，沒有 `cbnz w19` 或等價分支，`MAPPED` 的清除在 `0xffffffc010a1442c`／`0xffffffc010a14430` 無條件執行。

**(d) `kgsl_free_pool_pages`（`0xffffffc010a20198`）：** 依序載入 `[x19,#96]`（`memdesc->pages`）、`[x19,#104]`（`page_count`），直接 `bl kgsl_pool_free_pages`；整段沒有讀取 `priv` 欄位，也沒有 `tst`／`tbz` 測 `MAPPED` 位元。

`.296` 源碼與核心 ELF 在四個位置都缺少修補，裝置因此具備這條鏈所需的三個前置條件。

## 8. 可達性論證

### 8.1 主線的使用者可控 memdesc 寫入

PoC 對 `memdesc` 的寫入集中在 `:5392-5400`，依序寫入（相對於 victim entry）：

| 偏移 | 欄位 | 值 |
|---|---|---|
| `0x48`／`0x4c` | `memdesc.ops` | `kgsl_contiguous_ops` 的 runtime 位址 |
| `0x30`／`0x34` | `memdesc.size` | `LOW_SIZE = 0xC0000000`（3 GiB） |
| `0x28`／`0x2c` | `memdesc.physaddr` | `LOW_BASE = 0x80000000` |

這六個 32-bit word 透過 dangling SMMU PTE 寫入，沒有經過任何 KGSL ioctl 直接寫 `memdesc`。寫入後，PoC 在 `:5415` 以 `mmap(NULL, LOW_SIZE, …, kgsl_fd, vid << 12)` 建立 CPU 映射，fault 時進入 `kgsl_contiguous_vmfault()`。

### 8.2 未修 primitive 不能獨立觸達

在已 audit 的 KGSL ioctl 與初始化路徑中，`memdesc` 的三個關鍵欄位有這些寫入點（非窮舉）：

| 欄位 | 裝置 `.296` 的寫入點 | 性質 |
|---|---|---|
| `ops` | `kgsl_sharedmem.c:1135,1163,1222,1225,1281` | 全部是靜態 ops table，依配置型別指定 |
| `physaddr` | `kgsl_sharedmem.c:1232` | 配置時由 allocator 設定 |
| `size` | `kgsl_sharedmem.c:1173,1233,1254` | 來自驗證過的 size（使用者、dma_buf 或 DT） |
| `gpuaddr` | `kgsl.c:2567-2573`、`kgsl.c:3990-3998` | 只在 `kgsl_mmu_set_svm_region()` 成功後寫入使用者 hostptr |

其他寫入點同樣不改變結論：usermem import 在 `kgsl.c:2560`／`:2562` 寫 `size`／`ops`，dmabuf import 在 `kgsl.c:2985-2986`、`:3041`、`:3050` 寫 `size`／`ops`，probe 期的 `kgsl_allocate_global_fixed()` 在 `kgsl_sharedmem.c:1334-1335` 寫 `physaddr`／`size`；這些都是靜態 ops table、DT 設定值或經驗證的 size。內部路徑 `kgsl_iommu_get_gpuaddr()` 的 `memdesc->gpuaddr = addr`（`kgsl_iommu.c:2266`）使用內部選擇的位址。`ops`／`physaddr`／`size` 要變成攻擊者控制的值，必須先有寫入任意核心記憶體的 primitive；這條鏈的 primitive 是第四環節的 dangling SMMU PTE，被 23373 的修補擋住。

### 8.3 範圍與邊界

**只針對這條鏈與已 audit 的 KGSL ioctl 介面。** 證明的是這條特定資料流；若存在另一個未編號的 memdesc corruption，`ops`／`physaddr`／`size` 可能被重新控制。`.337` 源碼缺失、cred／pkey 半段未 audit、非窮盡搜尋這三項邊界見 §11.2 第 3–5 項。

## 9. 上游仍未修補的部分

9.1–9.3 在 Qualcomm `msm-5.4` `LA.UM.9.14.1.c26` 與 AOSP redbull 4.19 `android14-qpr3` 的 head 上仍然存在；9.4 是 mainline arm64 的 generic 行為；9.5 是 rbtree 比較的殘留 gap。它們是取得記憶體腐敗之後用來擴大控制的 primitive，不是鏈的入口。

| # | 位置 | 缺的檢查 | 後果 |
|---|---|---|---|
| 9.1 | `kgsl_contiguous_vmfault()`：5.4 `kgsl_sharedmem.c:569-580`、裝置 `:568-579`、AOSP 4.19 `:655-674` | `physaddr` 是否在 RAM、`physaddr + offset*PAGE_SIZE` 是否在 `size` 內、PFN 是否屬於此 memdesc | 改 `physaddr` 即把任意實體頁映射進 process |
| 9.2 | `kgsl_gpumem_vm_fault()`：5.4 `kgsl.c:3940-3950`、裝置 `:3887-3897`、AOSP 4.19 `:4768-4777` | 只檢查 `entry`／`ops`／`ops->vmfault` 非 NULL，不檢查 ops 型別與 PFNMAP flags | 把 pool 物件的 `ops` 換成 `kgsl_contiguous_ops` 後照常 dispatch |
| 9.3 | `kgsl_paged_vmfault()`：5.4 `kgsl_sharedmem.c:444-457`、裝置 `:443-456` | 只檢查 `offset >= size`；`pages[pgoff]` 可為 NULL 或非此物件的 page | 以 `pages[]` 指向任意 `struct page` |
| 9.4 | arm64：mainline `include/linux/pgtable.h:2249-2252` 的預設 `pfn_modify_allowed()` 回傳 true；`arch/arm64/include/asm/pgtable.h` 無 `__HAVE_ARCH_PFN_MODIFY_ALLOWED`（grep 計數 0）；`mm/memory.c:2909,2967,3056` 呼叫它 | PFN 所有權與 RAM 歸屬 | `vmf_insert_pfn()` 不做最後一層檢查 |
| 9.5 | 5.4 `kgsl_iommu.c:2209-2214` | rbtree 比較仍用 `gpuaddr + size <= start`，不檢查加法 | 未來 caller 傳入未檢查 size 時可再造反向 entry |

9.4 的行號為 2026-10-19 抓取 mainline `plain/` 時的結果，該 URL 指向 moving target。

## 10. 修補狀態與優先序

### 10.1 修補對照

| 缺陷 | 修補 commit | 分支 | 修補內容 | 已修分支的位置（直接抓取） | 裝置 `.296` 源碼 |
|---|---|---|---|---|---|
| 33107 | `d66b799c804083ea5226cfffac6d6c4e7ad4968b` | msm-4.19 | 拒絕 `end <= gpuaddr`，並以同一個 `end` 做範圍比較 | Qualcomm msm-5.4 `LA.UM.9.14.1.c26`：`kgsl_iommu.c:2173-2177`；AOSP redbull 4.19：`kgsl_iommu.c:2442-2446` | 缺少，`:2169-2183` |
| 21468 | `8376c8700f5badce175f897b2cb18a513278d703`；5.15 為 `3cbca5d2eeec99c8e0c6f8621dd62337323ae850` | msm-4.4／msm-5.15 | 快速路徑檢查 `arm_lpae_init_pte()` 的回傳值 | Qualcomm msm-5.4 c26：`io-pgtable-arm.c:661-665`；AOSP redbull 4.19：`io-pgtable-arm.c:648-652` | 缺少，`:655-662` |
| 23373（提早返回） | `330843f54465ee9b62e1a1e2f6c5d12b14c3b548`；AOSP 對應 `4ac1a9e2136c46e03cc0f79f26c9d8188d6f6f49` | msm-5.4／AOSP 4.19 | `kgsl_mmu_unmap()` 在 `mmu_unmap()` 失敗時提前返回 | Qualcomm msm-5.4 c26：`kgsl_mmu.c:461-462`；AOSP redbull 4.19：`kgsl_mmu.c:493-495` | 缺少，`:460-470` |
| 23373（pool 守衛） | `330843f5` | msm-5.4 | `kgsl_free_pool_pages()` 等 free op 檢查 `MAPPED` | Qualcomm msm-5.4 c26：`kgsl_sharedmem.c:1020-1021` | 缺少，`:1001-1015` |
| 23373（ion／anon 守衛） | `8fd4291171807099c9c8992404ea90f3202959a7`；4.4 為 `54aa44db11806c6d29fa85c23d2203f79c8fa9fe` | msm-5.4／msm-4.4 | `kgsl_destroy_ion()`、`kgsl_destroy_anon()` 檢查 `MAPPED` | Qualcomm msm-5.4 c26：`kgsl.c:322,374`；AOSP redbull 4.19：`kgsl.c:285,341` | 缺少，`kgsl.c:315-364` |

抓取來源：CodeLinaro 的 commit patch URL（`https://git.codelinaro.org/clo/la/kernel/<tree>/-/commit/<hash>.patch`）、AOSP 的 `https://android.googlesource.com/kernel/msm/+/<hash>?format=TEXT`，以及 `https://source.android.com/docs/security/bulletin/2024-07-01`。

### 10.2 修補優先序

三個缺陷位於不同函式、彼此獨立，完整防護需要三組都在；任一組都能讓這條鏈在對應階段停住。23373 的修補必須包含**提早返回 + 所有 free op 的 `MAPPED` 守衛**：只套用 ASB 2024-07-01 列的 ion／anon 守衛，pool 物件路徑會繼續可達（§5.3），修補清單要以實際 free op 為準。

## 11. 附錄

### 11.1 Commit 解析表

metadata 取自 CodeLinaro API 或 Android Gitiles JSON；「日期」為 committer date。CodeLinaro 的 HTML 頁面短時間連續抓取會回 HTTP 429（rate limit），hash 存在性以 API 的 commit object 確認。

| 樹 | Commit（日期） | 角色 |
|---|---|---|
| Qualcomm msm-5.4 | `f36244b8be1e08966bc829044a57629cef8c9c0b`（2026-09-07） | 分支 head（`msm: eva: UAF fix for race between map and unmap persist`），非這三個缺陷的修補 |
| Qualcomm msm-5.4 | `970275cba23e35055f90d60e3ff643ddb4da84ca`（2023-09-25）、`4bd2701df001c53dbbeb334eddeb4dd48f252c17`（2023-10-02） | 33107，兩個 backport |
| Qualcomm msm-5.4 | `a0ad1961666eaa4b1bba58b57353c3bbf9848b3a`（2023-09-22）、`9191906adfd674e6f647b2c3289751de914addac`（2023-09-25） | 21468，兩個 backport |
| Qualcomm msm-5.4 | `330843f54465ee9b62e1a1e2f6c5d12b14c3b548`（2023-11-30）、`7eef634530d2a00fd3992aa26a3845b09d37fe21`（2023-12-12，cherry-pick） | 23373：提早返回 + sharedmem guards |
| Qualcomm msm-5.4 | `8fd4291171807099c9c8992404ea90f3202959a7`（2024-02-14） | 23373：`kgsl.c` ion/anon guards |
| AOSP `kernel/msm` | `500b3a2059c1eec0fec08ec56add06320ea901a8`（2024-06-03） | 分支 head（`BACKPORT: net: fix __dst_negative_advice() race`） |
| AOSP `kernel/msm` | `77de1a60f1fbb6d5a58376403e24c6ecebd12c17`（2023-10-17，author 2023-09-08） | 33107 |
| AOSP `kernel/msm` | `1008723277d9c7909aa18a297ae23c39befbf0fc`（2023-10-17，author 2023-09-15） | 21468 |
| AOSP `kernel/msm` | `4ac1a9e2136c46e03cc0f79f26c9d8188d6f6f49`（2024-02-14，author 2023-11-29） | 23373：提早返回 + page-alloc/cma guards |
| AOSP `kernel/msm` | `63ef4e33a96e44419b2a3cdeb2e2dc10905d8910`（2024-04-03，author 2023-12-20） | 23373：ion/anon guards |

URL 形式：`https://git.codelinaro.org/clo/la/kernel/msm-5.4/-/commit/<hash>`、`https://android.googlesource.com/kernel/msm/+/<hash>`。其他樹上的原始修補：`d66b799c`（msm-4.19，2023-09-28）、`8376c870`（msm-4.4，2023-09-25）、`3cbca5d2`（msm-5.15，2023-10-09）、`54aa44db`（msm-4.4，2024-02-01）、`fd6b05db`（graphics-kernel，2024-01-30）。

**驗證陷阱：** `1008723277d9` 的 commit message 有一行 `Provenance: https://git.codelinaro.org/clo/la/kernel/msm-4.19/-/commit/1e46e81dbeb69aafd5842ce779f07e617680fd58`，但 `1e46e81d` 的實際標題是 `msm: kgsl: Limit the syncpoint count for AUX commands`，不是 `init_pte` 修補。

### 11.2 未驗證與推論清單

1. **修補後核心的動態結果：** 沒有在帶完整修補的核心上執行 PoC；§6 與 §8 的斷鏈、可達性論證都是 source trace 的 `[推論]`。
2. **rbtree 旋轉與 level-3 計數：** 反向 entry 讓重疊搜尋漏掉 A 的完整紅黑樹旋轉沒有重新推導；回滾清掉 level-2 entry 並釋放 level-3 table 的過程也是 source trace，沒有重跑實驗。
3. **`.337` 與 flashed image 的 byte identity：** `.337` 源碼不可取得；分析用的核心 ELF 沒有裝置端 hash／build id 可證明與 flashed image 逐位元組相同。
4. **全域 absence：** 沒有對整棵核心樹做窮盡的 memdesc 寫入搜尋。
5. **credential／pkey 半段：** 沒有對 5.15／6.1 的 cred／pkey 佈局做 audit。
6. **CVE 與 commit 的 vendor 對應：** ASB 2024-07-01 的 23373 列直接給出 `54aa44db` 與 `fd6b05db`；其餘修補（`330843f5`、`7eef6345`、`8fd42911`、`4ac1a9e2`、`63ef4e33`）不在該列中，對應由機制與 commit 內容相互印證。Qualcomm 公告頁是 JavaScript SPA，NVD 只連到該頁。

### 11.3 外部參照

- NVD CVE-2023-33107：<https://nvd.nist.gov/vuln/detail/CVE-2023-33107>
- NVD CVE-2024-21468：<https://nvd.nist.gov/vuln/detail/CVE-2024-21468>
- NVD CVE-2024-23373：<https://nvd.nist.gov/vuln/detail/CVE-2024-23373>
- ASB 2024-07-01：<https://source.android.com/docs/security/bulletin/2024-07-01>
- Qualcomm `msm-5.4` 分支 head：<https://git.codelinaro.org/clo/la/kernel/msm-5.4/-/commit/f36244b8be1e08966bc829044a57629cef8c9c0b>
- AOSP `kernel/msm` 分支 head：<https://android.googlesource.com/kernel/msm/+/500b3a2059c1eec0fec08ec56add06320ea901a8>
- Mainline `include/linux/pgtable.h`：<https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/plain/include/linux/pgtable.h>
- Mainline `arch/arm64/include/asm/pgtable.h`：<https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/plain/arch/arm64/include/asm/pgtable.h>
- Mainline `mm/memory.c`：<https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/plain/mm/memory.c>
