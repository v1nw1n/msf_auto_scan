# msf_auto_scan

## start msf rpc service  
```bash
msfrpcd -a 127.0.0.1 -U mssf -P ms3ff -f -s
```
## ruby install
```bash
apt-get install ruby-full libgmp-dev
gem install msfrpc-client  bundler parallel concurrent-ruby
```
## prepare target
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
