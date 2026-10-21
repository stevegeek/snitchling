fn main() {
    tonic_prost_build::configure()
        .build_client(true) // the client side is only used by tests, to play the daemon
        .compile_protos(&["proto/ui.proto"], &["proto"])
        .expect("compiling proto/ui.proto");

    slint_build::compile_with_config(
        "ui/app.slint",
        slint_build::CompilerConfiguration::new().with_style("fluent".into()),
    )
    .expect("compiling ui/app.slint");
}
