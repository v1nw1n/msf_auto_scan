#!/usr/bin/ruby -w
# -*- coding: UTF-8 -*-

require 'msfrpc-client'
require 'parallel'
require 'concurrent-ruby'

class ServiceScanner
  PORT_MAP = {
    21 => 'ftp',
    22 => 'ssh',
    23 => 'telnet',
    25 => 'smtp',
    111 => 'nfs',
    137 => 'netbios',
    138 => 'netbios',
    139 => 'netbios',
    389 => 'ldap',
    445 => 'smb',
    3389 => 'rdp'
    5432 => 'postgresql',
    6379 => 'redis',
    27017 => 'mongodb'
  }

  SERVICENAME_MAP = {
    'Microsoft-DS' => 'smb'
  }

  MODULE_MAP = {
    'ftp' => ['auxiliary/scanner/ftp/anonymous'],
    'ldap' => ['auxiliary/scanner/ldap/ldap_login'],
    'telnet' => ['auxiliary/scanner/telnet/telnet_login'],
    'smtp' => ['auxiliary/scanner/smtp/smtp_relay'],
    'smb' => ['auxiliary/scanner/smb/smb_version'],
    'rdp' => [
      'auxiliary/scanner/rdp/cve_2019_0708_bluekeep'
    ],
    'nfs' => ['auxiliary/scanner/nfs/nfsmount'],
    'mongodb' => ['auxiliary/scanner/mongodb/mongodb_login']
    'redis' => ['auxiliary/scanner/redis/redis_server',
                'exploit/linux/redis/redis_replication_cmd_exec', 
                'auxiliary/scanner/redis/redis_login',
                'auxiliary/scanner/redis/file_upload', 
                'exploit/linux/redis/redis_debian_sandbox_escape'],
    'postgresql' => ['multi/postgres/postgres_copy_from_program_cmd_exec'],
    'smb' => ['auxiliary/scanner/smb/smb_ms17_010'],
    'netbios' => ['auxiliary/scanner/netbios/nbname']
  }

  

  def initialize(file_path, log_file = 'scan_results.log')
    @file_path = file_path
    @log_file = log_file
     @rpc_client = Msf::RPC::Client.new(host: '127.0.0.1', port: 55553)
    @rpc_client.login('*', '*')
    @mutex = Mutex.new
    @pool = Concurrent::FixedThreadPool.new(10) # 动态调整线程数，根据实际情况调节
  end

  def run
    targets = File.readlines(@file_path).map do |line|
      ip, port, service = line.strip.split(':')
      { ip: ip, port: port.to_i, service: service }
    end

    targets.each do |target|
      @pool.post do
        service = identify_service(target)
        if service
          run_modules(service, target[:ip], target[:port])
        else
          log("未知服务: IP=#{target[:ip]}, Port=#{target[:port]}, Service=#{target[:service]}")
        end
      end
    end

    @pool.shutdown
    @pool.wait_for_termination
  end

  private

  def identify_service(target)
    # 检查service字段
    if MODULE_MAP.key?(target[:service])
      return target[:service]
    end
    service_from_servicename = SERVICENAME_MAP[target[:service]]
    if MODULE_MAP.key?(service_from_servicename)
      return service_from_servicename
    end 
    #检查port字段
    service_from_port = PORT_MAP[target[:port]]
    if MODULE_MAP.key?(service_from_port)
      return service_from_port
    end
    # 服务识别失败
    nil
  end

  def run_modules(service, ip, port)
    module_names = MODULE_MAP[service]
    return unless module_names

    module_names.each do |module_name|
      begin
        result = @rpc_client.call('module.execute', 'auxiliary', module_name, {
          'RHOSTS' => ip,
          'RPORT' => port
        })
        log("模块 #{module_name} 执行成功: IP=#{ip}, Port=#{port}, 结果: #{result}")

        job_id = result['job_id']
        uuid = result['uuid']

        monitor_job(job_id, uuid, module_name, ip, port)
      rescue => e
        log("执行模块 #{module_name} 失败: #{e.message}")
      end
    end
  end

  def monitor_job(job_id, uuid, module_name, ip, port)
    job_status = @rpc_client.call('job.list')[job_id.to_s]

    while job_status
      sleep(5) 
      job_status = @rpc_client.call('job.list')[job_id.to_s]
    end

    log("作业 #{job_id} 完成，获取结果...")
    result = @rpc_client.call('module.results', uuid)
    log("模块 #{module_name} 的结果: IP=#{ip}, Port=#{port}, 结果: #{result}")
  end

  def log(message)
    @mutex.synchronize do
      File.open(@log_file, 'a') do |f|
        f.puts message
      end
      puts message
    end
  end
end


file_path = 'ips_and_ports.txt'
scanner = ServiceScanner.new(file_path)
scanner.run
