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
  fetch_blocklist = pkgs.writeShellApplication {
    name = "run";
    runtimeInputs = [ pkgs.curl ];
    text = ''
      curl https://raw.githubusercontent.com/hagezi/dns-blocklists/main/hosts/pro.txt | grep -v '^#' | cut -f2 -d' ';
    '';
  };
  dump_lo = pkgs.writeShellApplication {
    name = "run";
    runtimeInputs = [ pkgs.tcpdump ];
    text = ''
      sudo tcpdump -i lo dst localhost
    '';

  };
}
