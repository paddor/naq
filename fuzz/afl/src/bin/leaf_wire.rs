fn main() {
    afl::fuzz!(|data: &[u8]| naq_fuzz::leaf_wire(data));
}
