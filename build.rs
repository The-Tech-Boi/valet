// The exe icon (Explorer, taskbar) and the windows' title-bar icon come from this resource.
fn main() {
    println!("cargo:rerun-if-changed=assets/valet.ico");
    embed_resource::compile("assets/valet.rc", embed_resource::NONE).manifest_optional().unwrap();
}
