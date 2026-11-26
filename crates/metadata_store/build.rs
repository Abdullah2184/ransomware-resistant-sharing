fn main() {
    // Ensure Cargo recompiles `sqlx::migrate!` whenever migration SQL files are added or changed.
    println!("cargo:rerun-if-changed=migrations");
}
