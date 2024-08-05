#!/bin/bash

# target
input_file="target.txt"
# res
result_file="ips_and_ports.txt"

# file exist check
if [[ ! -f "$input_file" ]]; then
  echo "文件 $input_file 不存在"
  exit 1
fi
echo > ips_and_ports.txt
#echo "start..."
while IFS=$' \t' read -r ip port; do
  echo "[debug]readline: '$ip' '$port'"
  # check ip and port
  if [[ -n "$ip" && -n "$port" ]]; then
    echo "[debug]connecting: $ip:$port"
    #某些版本的nc不支持 -G选项：设置建立连接的超时时间；-w：建立连接及数据传输的超时时间
    #output=$(nc -z -v -G 3 "$ip" "$port" 2>&1)
    output=$(nc -z -v -w 3 "$ip" "$port" 2>&1)
    echo "[debug]nc output: $output"
    # check alive
    if echo "$output" | grep -q "succeeded"; then
      service=$(echo "$output" | sed -n 's/.*\[\(.*\/\)\(.*\)\].*/\2/p')
      echo "$ip:$port:$service" >> "$result_file"
    else
      echo "[debug]----connect fail----: $ip $port"
    fi
  else
    echo "[debug]format error:'$ip' '$port'"
  fi
done < "$input_file"

echo "[debug]finish save res into: $result_file"
