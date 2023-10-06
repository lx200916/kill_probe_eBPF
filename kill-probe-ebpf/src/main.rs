#![no_std]
#![no_main]
mod vmlinux;
use aya_bpf::{
    helpers::{
        bpf_get_current_pid_tgid, bpf_get_current_task, bpf_get_current_uid_gid,
        bpf_probe_read_kernel,
    },
    macros::{map, tracepoint},
    maps::{HashMap, PerfEventArray,},
    programs::TracePointContext,
};
use aya_log_ebpf::{debug, info};
use kill_probe_common::Data;
use vmlinux::task_struct;
#[map]
static mut EVENTS: HashMap<u64, Data> = HashMap::pinned(1024, 0);
#[map]
static mut EVENTS_MAP: PerfEventArray<Data> = PerfEventArray::with_max_entries(0, 0);
#[tracepoint(category = "syscalls", name = "sys_enter_kill")]
pub fn kill_probe(ctx: TracePointContext) -> u32 {
    match try_kill_probe(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret as u32,
    }
}
#[tracepoint(category = "syscalls", name = "sys_exit_kill")]
pub fn kill_exit_probe(ctx: TracePointContext) -> u32 {
    match try_kill_probe_exit(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret as u32,
    }
}
fn try_kill_probe_exit(ctx: TracePointContext) -> Result<u32, i64> {
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let tid = bpf_get_current_pid_tgid() as u32;
    let ret = unsafe { ctx.read_at::<i64>(16)? };
    let uid_pid = bpf_get_current_uid_gid();
    let uid = (uid_pid >> 32) as u32;
    let gid = uid_pid as u32;
    // info!(
    //     &ctx,
    //     "tracepoint sys_exit_kill called: pid: {}, tid: {}, ret: {}", pid, tid, ret
    // );
    if pid < 4194304 {
        debug!(
            &ctx,
            "tracepoint sys_exit_kill called: pid: {}, tid: {}, ret: {}", pid, tid, ret
        );
        // info!(&ctx, "tracepoint sys_exit_kill called");
        // Check if exists in map
        let pid_tgid = ((pid as u64) << 32 | tid as u64) as u64;
        unsafe {
            let val_data = EVENTS.get(&pid_tgid);
            if let Some(data) = val_data {
                let mut data = data.clone();
                data.ret = ret;
                let _ = EVENTS.remove(&pid_tgid);
                if data.sig > 0 && (data.killed_pid < 4194304) {
                    EVENTS_MAP.output(&ctx, &data, 0);
                }
            } else {
                let _ = EVENTS.insert(
                    &pid_tgid,
                    &Data {
                        rgid: -1,
                        ruid: -1,
                        uid,
                        gid,
                        pid,
                        tid,
                        killed_pid: 0,
                        sig: 0,
                        ret: ret,
                    },
                    0,
                );
            }
        }
    }

    Ok(0)
}
#[tracepoint(category = "syscalls", name = "sys_enter_setuid")]
pub fn setuid_enter_probe(ctx: TracePointContext) -> u32 {
    match try_setuid_enter_probe(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret as u32,
    }
}
fn try_setuid_enter_probe(ctx: TracePointContext) -> Result<u32, i64> {
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let tid = bpf_get_current_pid_tgid() as u32;
    let uid = unsafe { ctx.read_at::<u64>(16)? };
    let uid_pid = bpf_get_current_uid_gid();
    let ruid = (uid_pid >> 32) as u32;
    let rgid = uid_pid as u32;
    info!(
        &ctx,
        "tracepoint sys_enter_setuid called: pid: {}, tid: {}, uid: {} ruid:{} rguid:{}",
        pid,
        tid,
        uid,
        ruid,
        rgid
    );
    Ok(0)
}

fn try_kill_probe(ctx: TracePointContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let tid = bpf_get_current_pid_tgid() as u32;
    let killed_pid = unsafe { ctx.read_at::<u64>(16)? };
    let sig = unsafe { ctx.read_at::<u64>(24)? };
    let uid_pid = bpf_get_current_uid_gid();
    let uid = (uid_pid >> 32) as u32;
    let gid = uid_pid as u32;
    let mut ppid = -1;

    let mut real_uid = -1;
    let mut real_gid = -1;
    let mut it: i32 = 0;
    if uid == 0 {
        // info!(
        //     &ctx,
        //     "Check if sudo?");
        // sudo
        let task = unsafe { bpf_get_current_task() } as *const task_struct;
        let mut parent = unsafe { bpf_probe_read_kernel(&(*task).real_parent)? };
        while it < 10 {
            it += 1;
            let parent_pid = unsafe { bpf_probe_read_kernel(&(*parent).tgid)? };
            // info!(
            //     &ctx,
            //     "Check if sudo? parent_pid: {}", parent_pid);
            if parent_pid == 1 {
                break;
            }
            let parent_cred = unsafe { bpf_probe_read_kernel(&(*parent).real_cred)?};
            let parent_uid = unsafe { bpf_probe_read_kernel(&(*parent_cred).uid.val)? };
            let parent_gid = unsafe { bpf_probe_read_kernel(&(*parent_cred).gid.val)? };
            if parent_uid != 0 {
                // Catch U!
                // info!(
                //     &ctx,
                //     "tracepoint sys_enter_kill called sudo: pid: {}, tid: {}, killed_pid: {}, sig: {} uid: {}, gid: {} ruid:{} rgid:{}",
                //     pid, tid, killed_pid, sig, uid, gid, parent_uid, parent_gid);
                real_uid = parent_uid as i32;
                real_gid = parent_gid as i32;
                ppid = parent_pid as i32;
                break;
            }
            parent = unsafe { bpf_probe_read_kernel(&(*parent).real_parent)? };
        }
    }else{
        real_gid = gid as i32;
        real_uid = uid as i32;
    }

    //     &ctx,
    //     "tracepoint sys_exit_kill called: pid: {}, tid: {}, killed_pid: {}, sig: {} uid: {}, gid: {}",
    //     pid, tid, killed_pid, sig, uid, gid
    // );
    // info!(&ctx, "tracepoint sys_enter_kill called");
    unsafe {
        let val_data = EVENTS.get(&pid_tgid);
        if let Some(data) = val_data {
            let mut data = data.clone();
            data.killed_pid = killed_pid;
            data.sig = sig;
            data.ruid = real_uid as i32;
            data.rgid = real_gid as i32;
            let _ = EVENTS.remove(&pid_tgid);
            if data.sig > 0 && (data.killed_pid < 4194304) {
                EVENTS_MAP.output(&ctx, &data, 0);
            }
        } else {
            let _ = EVENTS.insert(
                &pid_tgid,
                &Data {
                    rgid: real_gid as i32,
                    ruid: real_uid as i32,
                    uid,
                    gid,
                    pid,
                    tid,
                    killed_pid,
                    sig,
                    ret: 99,
                },
                0,
            );
        }
    }

    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
