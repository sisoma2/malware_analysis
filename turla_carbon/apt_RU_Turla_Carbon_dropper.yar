rule apt_RU_Turla_Carbon_Dropper : apt {

meta:
	author = "@sisoma2"
	date = "27/08/2020"
	desc = "Detects the Turla Carbon Dropper"
	hash = "a6efd027b121347201a3de769389e6dd"
	hash = "F45574C4CC4AED2DD1B23027434E9B06"
	version = "0.1"
	
strings:
	$strgrp1_1 = "viIta" nocase wide ascii
	$strgrp1_2 = "S-1-16-12288" nocase wide ascii
	$strgrp1_3 = "S:(ML;;NW;;;S-1-16-0)" nocase wide ascii
	$strgrp1_4 = "A;OICIID;GA" nocase wide ascii
	
	$strgrp2_1 = "Virtual Private Network Routing Service" nocase wide ascii
	$strgrp2_2 = "Health Key and Certificate Management Service" nocase wide ascii
	$strgrp2_3 = "System Restore Service" nocase wide ascii
	$strgrp2_4 = "Alerter" nocase wide ascii
	
	$code_x64 = { B9 00 20 00 00 FF 15 [4] 48 89 [1-6] 48 8D [1-6] 48 89 [1-6] 41 B9 00 20 00 00 4C 8B [1-6] 33 D? 48 8B [1-6] FF 15 [4] 85 C0 75 ?? FF 15 }
	$code_x86 = { 68 00 20 00 00 FF 15 [4] 83 C4 ?? 89 [1-6] 8D [1-6] 5? 68 00 20 00 00 8B [1-6] 5? 6A 00 8B [1-6] 5? FF 15 [4] 85 C0 75 ?? FF 15 }
	
condition:
	filesize < 1MB
	and 1 of ($code*)
	and any of ($strgrp1_*)
	and any of ($strgrp2_*)
}