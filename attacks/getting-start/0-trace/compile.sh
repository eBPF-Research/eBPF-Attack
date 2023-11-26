APP=trace
rm $APP

export BPF_CLANG=clang-14
go generate
go build -o $APP
sudo ./$APP