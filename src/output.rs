#[repr(C)]
#[derive(Debug)]
pub struct RawVec {
    pub ptr: i32,
    pub len: i32,
    // pub error: Option<Errors>,
}

// #[repr(C)]
// pub enum Errors {
//     A,
//     B,
//     C,
// }
