rule M_APT_VIRTUALPITA_1
{
       meta:
             author = "Mandiant"
             md5 = "fe34b7c071d96dac498b72a4a07cb246"
             description = "Finds opcodes to set a port to bind on 2233, encompassing the setsockopt(), htons(), and bind() from 40973d to 409791 in fe34b7c071d96dac498b72a4a07cb246"
		reference = "https://www.mandiant.com/resources/blog/esxi-hypervisors-malware-persistence"
      strings:
            $x = {8b ?? ?? 4? b8 04 00 00 00 [0 - 4] ba 02 00 00 00 be 01 00 00 00 [0 - 2] e8 ?? ?? ?? ?? 89 4? ?? 83 7? ?? 00 79 [0 - 50] ba 10 00 00 00 [0 - 10] e8}
      condition:
            uint32(0) == 0x464c457f and all of them  
}

rule M_APT_VIRTUALPITA_2
{
	meta:
		author = "Mandiant"
		md5 = "fe34b7c071d96dac498b72a4a07cb246"
		description = "Finds opcodes to decode and parse the recieved data in the socket buffer in fe34b7c071d96dac498b72a4a07cb246.  Opcodes from 401a36 to 401adc"
		reference = "https://www.mandiant.com/resources/blog/esxi-hypervisors-malware-persistence"
	strings:
            $x = {85 c0 74 ?? c7 05 ?? ?? ?? ?? fb ff ff ff c7 8? ?? ?? ?? ?? 00 00 00 00 e9 ?? ?? ?? ?? 4? 8b 05 ?? ?? ?? ?? 4? 83 c0 01 4? 89 05 ?? ?? ?? ?? c7 4? ?? 00 00 00 00 e9 ?? ?? ?? ?? 8b 4? ?? 4? 98 4? 8d 9? ?? ?? ?? ?? 4? 8d ?? e0 4? 8b 0? 4? 89 0? 4? 8b 4? ?? 4? 89 4? ?? 8b 4? ?? 4? 98 4? 8d b? ?? ?? ?? ?? b? ?? ?? ?? ?? e8 ?? ?? ?? ?? c7 4? ?? 00 00 00 00 eb ?? 8b 4? ?? 8b 4? ?? 01 c1 8b 4? ?? 03 4? ?? 4? 98 0f b6 9? ?? ?? ?? ?? 8b 4? ?? 4? 98 0f b6 8? ?? ?? ?? ?? 31 c2 4? 63 c1 88 9? ?? ?? ?? ?? 83 4? ?? 01}
      condition:
            uint32(0) == 0x464c457f and all of them  
}

rule M_APT_VIRTUALPITA_3
{
	meta:
		author = "Mandiant"
		md5 = "fe34b7c071d96dac498b72a4a07cb246"
		description = "Finds opcodes from 409dd8 to 409e46 in fe34b7c071d96dac498b72a4a07cb246 to set the HISTFILE environment variable to 'F' with a putenv() after loading each character individually."
		reference = "https://www.mandiant.com/resources/blog/esxi-hypervisors-malware-persistence"
      strings:
            $x = {4? 8b 4? ?? c6 00 48 4? 8b 4? ?? 4? 83 c0 05 c6 00 49 4? 8b 4? ?? 4? 83 c0 01 c6 00 49 4? 8b 4? ?? 4? 83 c0 06 c6 00 4c 4? 8b 4? ?? 4? 83 c0 02 c6 00 53 4? 8b 4? ?? 4? 83 c0 07 c6 00 45 4? 8b 4? ?? 4? 83 c0 03 c6 00 54 4? 8b 4? ?? 4? 83 c0 08 c6 00 3d 4? 8b 4? ?? 4? 83 c0 04 c6 00 46 4? 8b 4? ?? 4? 83 c0 09 c6 00 00 4? 8b 7? ?? e8}
	condition:
            uint32(0) == 0x464c457f and all of them       
}

rule M_APT_VIRTUALPITA_4
{
	meta:
		author = "Mandiant"
		md5 = "fe34b7c071d96dac498b72a4a07cb246"
		description = "Finds opcodes from 401f1c to 401f4f in fe34b7c071d96dac498b72a4a07cb246 to decode text with multiple XORs"
		reference = "https://www.mandiant.com/resources/blog/esxi-hypervisors-malware-persistence"
	strings:
            $x = {4? 8b 4? ?? 4? 83 c1 30 4? 8b 4? ?? 4? 8b 10 8b 4? ?? 4? 98 4? 8b 04 ?? ?? ?? ?? ?? 4? 31 c2 4? 8b 4? ?? 4? 83 c0 28 4? 8b 00 4? c1 e8 10 0f b6 c0 4? 98 4? 8b 04}
	condition:
		uint32(0) == 0x464c457f and all of them
}

rule M_Hunting_Script_LaunchAndDelete_1
{
	meta:
		author = "Mandiant"
		md5 = "bd6e38b6ff85ab02c1a4325e8af29ce4"
		description = "Finds scripts that launch and then delete files, indicative of cleaning up tracks and remaining in-memory only."
		reference = "https://www.mandiant.com/resources/blog/esxi-hypervisors-malware-persistence"
	strings:
		$ss = /setsid[^\n\r]{,250}-i[\r\n]{,5}rm/
	condition:
		all of them
}

rule M_Hunting_Python_Backdoor_CommandParser_1
{
      meta:
		author = "Mandiant"
		md5 = "61ab3f6401d60ec36cd3ac980a8deb75"
		description = "Finds strings indicative of the vmsyslog.py python backdoor."
		reference = "https://www.mandiant.com/resources/blog/esxi-hypervisors-malware-persistence"
      strings:
		$key1 = "readInt8()" ascii wide
		$key2 = "upload" ascii wide
		$key3 = "download" ascii wide
		$key4 = "shell" ascii wide
		$key5 = "execute" ascii wide
		$re1 = /def\srun.{,20}command\s?=\s?self\.conn\.readInt8\(\).{,75}upload.{,75}download.{,75}shell.{,75}execute/s
	condition:
		filesize < 200KB and all of them
}