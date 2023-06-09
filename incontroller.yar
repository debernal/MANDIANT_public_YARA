rule MTI_Hunting_AsRockDriver_Exploit_PDB
{
	meta:
		author = "Mandiant"
		date = "03-23-2022"
		description = "Searching for executables containing strings associated with AsRock driver Exploit."
		reference = "https://www.mandiant.com/resources/blog/incontroller-state-sponsored-ics-tool"
	strings:
		$dos_stub = "This program cannot be run in DOS mode"
		$pdb_bad = "dev projects\\SignSploit1\\x64\\Release\\AsrDrv_exploit.pdb"
		$pdb_good = "c:\\asrock\\work\\asrocksdk_v0.0.69\\asrrw\\src\\driver\\src\\objfre_win7_amd64\\amd64\\AsrDrv103.pdb" 
	condition:
		all of them and (@pdb_bad < @dos_stub[2]) and (#dos_stub == 2) and (@pdb_good > @dos_stub[2])
}

rule MTI_Hunting_AsRockDriver_Exploit_Generic
{
	meta:
		author = "Mandiant"
		date = "03-23-2022"
		description = "Searching for executables containing strings associated with AsRock driver Exploit."
		reference = "https://www.mandiant.com/resources/blog/incontroller-state-sponsored-ics-tool"
	strings:
		$dos_stub = "This program cannot be run in DOS mode"
		$pdb_good = "c:\\asrock\\work\\asrocksdk_v0.0.69\\asrrw\\src\\driver\\src\\objfre_win7_amd64\\amd64\\AsrDrv103.pdb"  

	condition:
		all of them and (#dos_stub == 2) and (@pdb_good > @dos_stub[2])
}