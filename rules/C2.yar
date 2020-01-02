
rule C2_Domain {
	meta:
		author = "Borhan Elkhouly"
		info= "Black list for C&C domains"
	strings:
		$s1 = "www.emich.edu" wide ascii
	condition:
		any of them
}


rule C2_IP {
	meta:
		author = "Borhan Elkhouly"
		info= "Black list for C&C IP addresses"
	strings:
		$s1 = "10.0.0.1" wide ascii
	condition:
		any of them
}
