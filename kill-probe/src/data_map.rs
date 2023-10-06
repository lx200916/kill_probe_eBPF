use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use kill_probe_common::Data;
#[derive(Debug, Clone,Default)]
pub struct DataMap {
    pub data: Arc<RwLock<HashMap<u64, Data>>>,
}
