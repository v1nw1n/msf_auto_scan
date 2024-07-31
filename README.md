# msf_auto_scan
根据识别的服务加载预设的MSF模块执行主机服务的漏洞扫描。
##   target prepare
```bash
vim target.txt
```
txt format:
`ip port`
eg. 1.2.3.4 3389
## target alive check
```bash
./nc_check_alive_status.sh
```
output:`ips_and_ports.txt`

##  msf rpc service  start
```bash
msfrpcd -a 127.0.0.1 -U mssf -P ms3ff -f -s
```
## ruby install
```bash
apt-get install ruby-full libgmp-dev
gem install msfrpc-client  bundler parallel concurrent-ruby
```
##  target modify
service字段需要按照ServiceScanner.rb中map的服务名适当修正。
或按照格式自行编辑ips_and_ports.txt
```bash
vim ips_and_ports.txt
```
txt format:
`ip:port:service`
eg. 1.2.3.4:3389:rdp
## run
```bash
chmod +x ServiceScanner.rb
./ServiceScanner.rb
```
or
```bash
ruby ServiceScanner.rb
```
