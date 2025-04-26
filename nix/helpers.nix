{ pkgs }:
{
  run = pkgs.writeShellApplication {
  name = "run";
  runtimeInputs = with pkgs; [
    rustup
    bpf-linker
    clang
  ];
  text = ''
    rustup check
    if [[ -z "''${BPF_HOLE_IFACE-""}" ]]; then
      echo "which interface should be listened on?"
      echo -------------------------------
      ifconfig | grep -v '^ ' | cut -f1 -d: | xargs echo
      echo -------------------------------

      echo BPF_HOLE_IFACE=

      read -r BPF_HOLE_IFACE
      export BPF_HOLE_IFACE
    fi
    RUST_LOG=info cargo run --config 'target."cfg(all())".runner="sudo -E"' -- --iface "''${BPF_HOLE_IFACE}"
  '';
  };
  dump_lo = pkgs.writeShellApplication {
    name = "dump_lo";
    runtimeInputs = [ pkgs.tcpdump ];
    text = ''
      sudo tcpdump -i lo dst localhost
    '';

  };
}
