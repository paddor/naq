fn main() {
    afl::fuzz!(|data: &[u8]| naq_fuzz::peer_frames(data));
}
