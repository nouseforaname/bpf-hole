{ pkgs }:
pkgs.writeShellApplication {
  name = "run";
  runtimeInputs = [ ];
  text = ''
    RUST_LOG=info cargo run --config 'target."cfg(all())".runner="sudo -E"' -- --iface "$BPF_HOLE_IFACE"
  '';
}
