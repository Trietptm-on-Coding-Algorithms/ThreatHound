
rule test {
	meta:
		author = "Borhan Elkhouly"
		info= "ThreatHound Test"

		strings:
			$s1 = "www.google.com" wide ascii
			$s2 = "www.emich.edu" wide ascii
			$s3 = "Lab01-01.dll" wide ascii
			$s4 = "WARNING_THIS_WILL_DESTROY_YOUR_MACHINE" wide ascii
		condition:
			any of them
}
