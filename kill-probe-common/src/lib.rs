#![no_std]

#[derive(Debug, Clone)]
#[repr(C)]
pub struct Data{
    pub uid: u32,
    pub gid: u32,
    pub pid: u32,
    pub tid: u32,
    pub killed_pid: u64,
    pub sig: u64,
    pub ret: i64,
    pub ruid: i32,
    pub rgid: i32,
}
#[repr(C)]
#[derive(Debug, Clone)]
pub struct RetData{
    pub pid: u32,
    pub tid: u32,
    pub ret: i64,
}
