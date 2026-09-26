//! Windows 采集。
//!
//! 走 `sysinfo`（内部用 Win32 API，**不调 WMI、不调 PowerShell** —— R18）。
//! 拿不到的两项如实声明，的三平台分界表：
//! - **负载**：Windows 没有 load average 这个概念
//! - **温度**：需要 WMI + 管理员权限

use std::time::{Duration, Instant};

use pulse_proto::{Capabilities, DiskUsage, Mem, Metrics, NetStat, RuntimeConfig};
use sysinfo::{
    CpuRefreshKind, Disks, MemoryRefreshKind, Networks, ProcessRefreshKind, ProcessesToUpdate,
    RefreshKind, System,
};

use super::{filter, gpu::Gpu, rate, Collector, Facts};

pub struct WindowsCollector {
    sys: System,
    disks: Disks,
    nets: Networks,
    gpu: Gpu,
    prev_net: Option<(u64, u64, Instant)>,
    /// 进程枚举比其他指标贵得多，按更低的频率刷新并缓存。
    procs: Option<(u32, Instant)>,
}

impl WindowsCollector {
    pub fn new() -> Self {
        let mut sys = System::new_with_specifics(
            RefreshKind::nothing()
                .with_cpu(CpuRefreshKind::nothing().with_cpu_usage())
                .with_memory(MemoryRefreshKind::everything()),
        );
        sys.refresh_cpu_usage();
        Self {
            sys,
            disks: Disks::new_with_refreshed_list(),
            nets: Networks::new_with_refreshed_list(),
            gpu: Gpu::probe(),
            prev_net: None,
            procs: None,
        }
    }

    /// 磁盘合计。**facts 与 sample 必须共用这一个实现** ——
    /// 之前 facts 里是一句没过滤的 `.map(total_space).sum`，
    /// 于是用户配了磁盘过滤后「静态信息里的磁盘总量」和「实时指标里的
    /// 磁盘总量」对不上（LM7）。Windows 没有 APFS 共享容器的双算问题，
    /// 只做挂载点过滤。
    fn disk_usage(&self, cfg: &RuntimeConfig) -> DiskUsage {
        let mounts: Vec<String> = self
            .disks
            .iter()
            .map(|d| d.mount_point().display().to_string())
            .collect();
        let picked = filter::select(&mounts, &cfg.disk_include, &cfg.disk_exclude);

        let (mut total, mut used) = (0u64, 0u64);
        for d in self.disks.iter() {
            let mp = d.mount_point().display().to_string();
            if !picked.contains(&&mp) {
                continue;
            }
            total += d.total_space();
            used += d.total_space().saturating_sub(d.available_space());
        }
        DiskUsage { total, used }
    }

    /// 进程数。枚举全部进程比其他指标贵一个数量级，所以按 [`PROC_REFRESH`]
    /// 的间隔刷新并缓存 —— 2 秒一次会让 agent 的 CPU 占用明显上去。
    ///
    /// 之前这儿是 `System::new()` 之后直接读 `processes().len()`：
    /// 新实例的进程列表是空的，不刷新就永远是 `Some(0)`（LM6）。
    /// macOS 侧是同一样的缓存模式，保持一致。
    fn process_count(&mut self) -> u32 {
        const PROC_REFRESH: Duration = Duration::from_secs(15);
        let stale = self
            .procs
            .is_none_or(|(_, at)| at.elapsed() >= PROC_REFRESH);
        if stale {
            self.sys.refresh_processes_specifics(
                ProcessesToUpdate::All,
                true,
                ProcessRefreshKind::nothing(),
            );
            self.procs = Some((self.sys.processes().len() as u32, Instant::now()));
        }
        self.procs.map(|(n, _)| n).unwrap_or(0)
    }
}

impl Default for WindowsCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl Collector for WindowsCollector {
    fn facts(&mut self, cfg: &RuntimeConfig) -> Facts {
        self.sys.refresh_memory();
        self.disks.refresh(true);
        self.nets.refresh(true);

        Facts {
            hostname: System::host_name().unwrap_or_else(|| "unknown".into()),
            os: System::long_os_version().unwrap_or_else(|| "Windows".into()),
            kernel: System::kernel_version(),
            arch: System::cpu_arch(),
            cpu_model: self
                .sys
                .cpus()
                .first()
                .map(|c| c.brand().trim().to_string()),
            cpu_cores: System::physical_core_count().unwrap_or(0) as u32,
            virtualization: None,
            mem_total: self.sys.total_memory(),
            swap_total: self.sys.total_swap(),
            disk_total: self.disk_usage(cfg).total,
            boot_at: System::boot_time() as i64,
            interfaces: self.nets.keys().cloned().collect(),
            capabilities: Capabilities {
                gpu_nvml: self.gpu.available(),
                temperature: false,  // 需要 WMI + 管理员
                load_average: false, // Windows 没有这个概念
                tcp_conn_count: false,
                proc_count: true,
                icmp_unprivileged: false, // 延迟监控走 TCP
                self_update: crate::update::available(),
                cgroup_limited: false,
            },
        }
    }

    fn sample(&mut self, cfg: &RuntimeConfig) -> Metrics {
        self.sys.refresh_cpu_usage();
        self.sys.refresh_memory();
        self.disks.refresh(false);
        self.nets.refresh(false);

        let names: Vec<String> = self.nets.keys().cloned().collect();
        let picked = filter::select(&names, &cfg.net_include, &cfg.net_exclude);
        let (mut rx, mut tx) = (0u64, 0u64);
        for (name, data) in self.nets.iter() {
            if picked.contains(&name) {
                rx += data.total_received();
                tx += data.total_transmitted();
            }
        }
        let now = Instant::now();
        let (rx_speed, tx_speed) = match self.prev_net.replace((rx, tx, now)) {
            Some((prx, ptx, pt)) => {
                let s = now.duration_since(pt).as_secs_f64();
                (rate(prx, rx, s), rate(ptx, tx, s))
            }
            None => (0, 0),
        };

        // 磁盘合计：与 facts 共用 disk_usage()，保证同一套过滤口径（LM7）
        let disk = self.disk_usage(cfg);
        let (dt, du) = (disk.total, disk.used);

        let total = self.sys.total_memory();
        Metrics {
            ts: crate::now_unix(),
            cpu_pct: pulse_proto::pct_to_basis_points(self.sys.global_cpu_usage()),
            load: [0; 3], // capabilities.load_average = false，前端会隐藏
            mem: Mem {
                total,
                free: self.sys.free_memory(),
                // Windows 的 ullAvailPhys 就是 available 语义；无 buff/cache 概念，
                // 所以「含缓冲」开关在这台机器上两种口径结果相同
                available: self.sys.available_memory(),
                buffers: 0,
                cached: 0,
                swap_total: self.sys.total_swap(),
                swap_free: self.sys.free_swap(),
            },
            disk: DiskUsage {
                total: dt,
                used: du,
            },
            net: NetStat {
                rx_bytes: rx,
                tx_bytes: tx,
                rx_speed,
                tx_speed,
                ifaces: picked.into_iter().cloned().collect(),
            },
            tcp_conn: None,
            udp_conn: None,
            proc_count: Some(self.process_count()),
            gpu: cfg.gpu_enabled.then(|| self.gpu.sample()).flatten(),
            cpu_temp: None,
            uptime_s: System::uptime(),
        }
    }
}
