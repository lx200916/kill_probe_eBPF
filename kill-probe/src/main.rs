use anyhow::{Ok, Result};
use aya::maps::AsyncPerfEventArray;
use aya::programs::TracePoint;
use aya::util::online_cpus;
use aya::{include_bytes_aligned, Bpf, BpfLoader};
use aya_log::BpfLogger;
use bytes::BytesMut;
use flexi_logger::{opt_format, Age, Cleanup, Criterion, Naming};
use kill_probe_common::Data;
use log::{debug, error, info, warn};
use reqwest::Client;
use serde_json::json;
use std::collections::HashMap;
use std::path::Path;
use std::sync::OnceLock;
use sysinfo::{ProcessExt, SystemExt};
use tokio::signal;
use uzers::get_user_by_uid;
static CLIENT: OnceLock<Client> = OnceLock::new();
static WHITE_LIST: OnceLock<Vec<u64>> = OnceLock::new();
static WHITE_NAME_LIST: [&'static str; 1] = ["systemd-udevd"];
#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let _logger = flexi_logger::Logger::try_with_env_or_str("info, my::critical::module=trace")?
        .format_for_files(opt_format)
        .rotate(
            // If the program runs long enough,
            Criterion::Age(Age::Day), // - create a new file every day
            Naming::Timestamps,       // - let the rotated files have a timestamp in their name
            Cleanup::KeepLogFiles(7), // - keep at most 7 log files
        )
        .log_to_file(flexi_logger::FileSpec::default())
        .write_mode(flexi_logger::WriteMode::BufferAndFlush)
        .start()?;
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {}", ret);
    }
    let _ = std::fs::remove_dir_all("/sys/fs/bpf/kill_probe/");
    std::fs::create_dir_all("/sys/fs/bpf/kill_probe/")?;
    let mut loader = BpfLoader::new();
    let loader = loader
        .map_pin_path(Path::new("/sys/fs/bpf/kill_probe/"))
        .allow_unsupported_maps();
    #[cfg(debug_assertions)]
    let bpf = loader.load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/kill-probe"
    ))?;
    #[cfg(target_os = "linux")]
    println!(
        "{:?}",
        WHITE_LIST.get_or_init(|| {
            let mut sys = sysinfo::System::new_with_specifics(
                sysinfo::RefreshKind::new()
                    .with_processes(sysinfo::ProcessRefreshKind::new().with_user()),
            );
            sys.refresh_all();
            let processes = sys.processes();
            return processes
                .into_iter()
                .filter(|(_, process)| {
                    for name in WHITE_NAME_LIST.into_iter() {
                        if process.name() == name {
                            // println!("{} {}", process.name(), process.pid());
                            // println!("{:?},{:?}", process.cwd(), process.user_id());
                            if let Some(uid) = process.user_id() {
                                if **uid ==0 && process.cwd()== Path::new("/"){
                                    if process.cmd().len() ==1 && process.cmd()[0].starts_with("/lib/systemd") {
                                        return  true;
                                    }
                                }

                        }
                        }
                    }
                    return false;
                })
                .map(|(pid, _)| sysinfo::PidExt::as_u32(*pid) as u64)
                .collect::<Vec<u64>>();
        })
    );
    #[cfg(not(target_os = "linux"))]
    WHITE_LIST.get_or_init(|| vec![]);

    #[cfg(not(debug_assertions))]
    let bpf = BpfLoader::new()
        .map_pin_path(Path::new("/sys/fs/bpf/kill_probe/"))
        .load(include_bytes_aligned!(
            "../../target/bpfel-unknown-none/release/kill-probe"
        ))?;
    //list all programs
    // let programs = bpf.programs();
    // for program in programs {
    //     info!("program name: {}", program.0);
    // }
    //Leak the BPF object so that it can be used by the async task.
    let mut bpf = Box::leak(Box::new(bpf));

    load_ebpf(&mut bpf, "kill_probe", "sys_enter_kill")?;
    load_ebpf(&mut bpf, "kill_exit_probe", "sys_exit_kill")?;
    // load_ebpf(&mut bpf, "setuid_enter_probe", "sys_enter_setuid")?;

    handle_enter_envent(bpf).await?;
    signal::ctrl_c().await?;
    Ok(())
}

fn load_ebpf(bpf: &mut Bpf, program_name: &str, trace_name: &str) -> Result<(), anyhow::Error> {
    if let Err(e) = BpfLogger::init(bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        // warn!("failed to initialize eBPF logger: {}", e);
    }
    let program: &mut TracePoint = bpf.program_mut(program_name).unwrap().try_into()?;
    program.load()?;
    program.attach("syscalls", trace_name)?;
    Ok(())
}
async fn handle_enter_envent(bpf: &'static mut Bpf) -> Result<(), anyhow::Error> {
    let cpus = online_cpus()?;
    let mut events = AsyncPerfEventArray::try_from(bpf.map_mut("EVENTS_MAP").unwrap())?;
    for cpu in cpus {
        let mut buf = events.open(cpu, None)?;
        tokio::task::spawn(async move {
            let mut buffers = (0..cpu)
                .map(|_| BytesMut::with_capacity(10240))
                .collect::<Vec<_>>();
            loop {
                let events = buf.read_events(&mut buffers).await;
                if events.is_ok() {
                    for i in 0..events.unwrap().read {
                        let event_ptr = &mut buffers[i];
                        let val_data =
                            unsafe { (event_ptr.as_ptr() as *const Data).read_unaligned() };
                        let _ = handle_kill(&val_data).await;
                        // let pid_tgid = ((val_data.pid as u64) << 32 | val_data.tid as u64) as u64;
                    }
                }
            }
        });
    }

    Ok(())
}
#[inline]
async fn handle_kill(data: &Data) -> Result<(), anyhow::Error> {
    if u64::from(data.pid) != data.killed_pid && (data.sig == 15 || data.sig == 9) {
        let mut data = data.clone();

        // info!(
        //     "pid: {}, tid: {}, killed_pid: {}, sig: {},ret: {:?} uid:{} gid:{} ruid:{} rgid:{}",
        //     data.pid, data.tid, data.killed_pid, data.sig, data.ret, data.uid, data.gid, data.ruid, data.rgid
        // );
        if data.ret < 0 {
            // Attempt to kill but failed.
            // Can We get more info from ERRNO?
            match data.ret {
                -1 => {
                    // EPERM
                    // Operation not permitted; the process does not have the
                    // required permissions, or some capability is missing from
                    // the calling process or effective user ID.
                    // We just log it.
                    let username =
                        get_username_from_uid(data.ruid).unwrap_or_else(|| "Unknown".to_string());

                    info!("Not permitted! pid: {}, tid: {}, killed_pid: {}, sig: {},ret: {:?} uid:{} gid:{} username:{}",
                        data.pid, data.tid, data.killed_pid, data.sig, data.ret, data.uid, data.gid, username
                    )
                }
                _ => {}
            }
        } else {
            if let Some(w) = WHITE_LIST.get() {
                if w.contains(&(data.pid.into())) {
                    return Ok(());
                }
                
            }
            if data.ruid < 0 {
                // We Failed to find Real UIDs.
                data.ruid = data.uid as i32;
                data.rgid = data.gid as i32;
            }
            // Attempt to kill and success.
            // We can get more info from data.ret.
            if i64::from(data.ruid) != i64::from(data.uid) {
                // We can get more info from data.ret.
                let username =
                    get_username_from_uid(data.ruid).unwrap_or_else(|| "Unknown".to_string());

                let message = format!("Attempt to kill with sudo and success. pid: {}, tid: {}, killed_pid: {}, sig: {},ret: {:?} uid:{} gid:{} ruid:{} rgid:{} uname:{}",
                    data.pid, data.tid, data.killed_pid, data.sig, data.ret, data.uid, data.gid, data.ruid, data.rgid, username
                );
                info!("{}", message);
                notify(message).await;
            } else {
                let username =
                    get_username_from_uid(data.ruid).unwrap_or_else(|| "Unknown".to_string());
                info!("Attempt to kill and success. pid: {}, tid: {}, killed_pid: {}, sig: {},ret: {:?} uid:{} gid:{} ruid:{} rgid:{} uname:{}",
                    data.pid, data.tid, data.killed_pid, data.sig, data.ret, data.uid, data.gid, data.ruid, data.rgid, username
                );
            }
        }
    } else {
        // Process Suicide, We do not care that.
    }
    Ok(())
}

fn get_username_from_uid(uid: i32) -> Option<String> {
    if uid < 0 {
        None
    } else {
        Some(get_user_by_uid(uid as u32).map(|s| s.name().to_string_lossy().to_string())?)
    }
}
async fn notify(message: String) {
    // let fs_token:Option<String> = std::env::var("FS_Token").ok();
    let fs_token = option_env!("FS_Token");
    if fs_token.is_none() {
        return;
    }
    let url = format!(
        "https://open.feishu.cn/open-apis/bot/v2/hook/{}",
        fs_token.unwrap()
    );
    let mut map: HashMap<&str, serde_json::Value> = HashMap::new();
    map.insert("msg_type", json!("text"));
    map.insert("content", json!({ "text": message }));
    let res = CLIENT
        .get_or_init(|| Client::new())
        .post(url)
        .json(&map)
        .send()
        .await;
    if res.is_err() {
        error!("{:?}", res.err())
    } else {
        debug!("{:?}", res.unwrap().text().await)
    }
}
