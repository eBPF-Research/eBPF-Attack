APP=cron
rm $APP
rm -rf *_log.txt

export BPF_CLANG=clang-13
go generate
go build -o $APP
sudo ./$APP