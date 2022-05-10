rule alina_malware_rule
{
meta: 
	description = "Rule for alina malware (spark)"
strings: 
	$mz = {4D 5A}
	$mal_str1 = /C:\Users\Benson\Desktop\ALIN\Source working\Debug\Spark.pdb/
	$mal_str2 = "\\\\.\\pipe\\spark"
	$mal_str3 = /C:\drv.sys/
	$mal_str4 = "7YhngylKo09H"
condition: 
	($mz at 0) and (any of ($mal_str*))
}