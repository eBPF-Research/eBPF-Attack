rm bash_hook

export BPF_CLANG=clang-13
go generate
go build -o bash_hook
sudo ./bash_hook