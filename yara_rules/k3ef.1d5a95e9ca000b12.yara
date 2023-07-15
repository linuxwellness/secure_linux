
rule k3ef_1d5a95e9ca000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3ef.1d5a95e9ca000b12"
     cluster="k3ef.1d5a95e9ca000b12"
     cluster_size="5"
     filetype = "PE32 executable (DLL) (console) Intel 80386 Mono/.Net assembly"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="kranet malicious attribute"
     md5_hashes="['284aa7668f63a0d71473911fe7eb3339','4e8741ad8ae886073c9535fcf59204fe','a159b8d2cc8cb1393bbf00276bc0ccb0']"

   strings:
      $hex_string = { 5a5f444154415f4552524f523a2063667461625b7b307d5d3d7b317d206c6173743d7b327d000073747265616d20636f727275707465640000626c6f636b5369 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
