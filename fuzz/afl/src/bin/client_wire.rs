fn main() {
    afl::fuzz!(|data: &[u8]| naq_fuzz::client_wire(data));
}
