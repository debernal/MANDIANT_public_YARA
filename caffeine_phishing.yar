rule M_Hunting_JS_Caffeine_Redirect_1
{
	meta:
		author = "adrian.mccabe"
		md5 = "60cae932b80378110d74fe447fa518d6"
		date_created = "2022-09-22"
		rev = "1"
		context = "Searches for string artifacts on Caffeine Javascript redirect pages. Intentionally wide."
		reference = "https://www.mandiant.com/resources/blog/caffeine-phishing-service-platform"
	strings:
		$cf1 = "Don't Play Here Kid" ascii wide
		$cf2 = "mrxc0der" ascii wide
	condition:
		all of them
}

rule M_Hunting_PHP_Caffeine_Toolmarks_1
{
    meta:
		author = "adrian.mccabe"
		md5 = " ce9a17f9aec9bd2d9eca70f82e5e048b"
		date_created = "2022-09-22"
		rev = "1"
		context = "Searches for generic Caffeine obfuscation toolmark strings. Intentionally wide."
		reference = "https://www.mandiant.com/resources/blog/caffeine-phishing-service-platform"
	strings:
		$attacker_brand = " - WWW.CAFFEINES.STORE" ascii wide
		$obfuscation_tagline = "CODED By MRxC0DER" ascii wide

	condition:
		all of them
}

rule M_Hunting_PHP_Caffeine_Obfuscation_1
{
	meta:
		author = "adrian.mccabe"
		md5 = "ce9a17f9aec9bd2d9eca70f82e5e048b"
		date_created = "2022-09-22"
		rev = "1"
		context = "Searches for obfuscated PHP scripts."
		reference = "https://www.mandiant.com/resources/blog/caffeine-phishing-service-platform"
	strings:
		$f1 = {3C 3F 70 68 70 }
		$a1 = "__FILE__));" ascii wide
		$a2 = "=NULL;@eval" ascii wide
		$a3 = "))));unset" ascii wide

	condition:
		uint16(0) == 0x3F3C and
		all of them
}

rule M_Hunting_JSON_Caffeine_Config_1
{
	meta:
		author = "adrian.mccabe"
		md5 = "684b524cef81a9ef802ed3422700ab69"
		date_created = "2022-09-22"
		rev = "1"
		context = "Searches for default Caffeine configuration syntax. Intentionally wide."
		reference = "https://www.mandiant.com/resources/blog/caffeine-phishing-service-platform"
	strings:
		$cf1 = "token" ascii wide
		$cf2 = "ip-api.io" ascii wide
		$cf3 = "ff57341d-6fb8-4bdb-a6b9-a49f94cbf239" ascii wide
		$cf4 = "send_to_telegram" ascii wide
		$cf5 = "telegram_user_id" ascii wide
	condition:
		all of them
}

rule M_Hunting_ICO_Caffeine_Favicon_1
{
	meta:
		author = "adrian.mccabe"
		md5 = "12e3dac858061d088023b2bd48e2fa96"
		date_created = "2022-09-22"
		rev = "1"
		context = "Searches for legitimate Microsoft favicon used by Caffeine. VALIDATION REQUIRED."
		reference = "https://www.mandiant.com/resources/blog/caffeine-phishing-service-platform"
	strings:
		$a1 = { 01 00 06 00 80 }
		$a2 = "fffffff" ascii wide
		$a3 = "3333333" ascii wide
		$a4 = "DDDDDDDDDDDUUUUUUUUUUUP" ascii wide
		$a5 = "UUUPDDD@" ascii wide
	condition:
		uint16(1) == 0x0100 and
		all of them
}