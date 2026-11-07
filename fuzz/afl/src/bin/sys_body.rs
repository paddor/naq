fn main() {
    afl::fuzz!(|data: &[u8]| naq_fuzz::sys_body(data));
}
