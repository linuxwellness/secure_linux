
rule o3e9_589abec9c4000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.589abec9c4000b12"
     cluster="o3e9.589abec9c4000b12"
     cluster_size="229"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virlock kazy nabucur"
     md5_hashes="['0876ff6820d743c756c8a1cb727dc648','0b3e58aee426d5f524b4def455c91b36','4d924c386209e843ba2f3ea141b30f57']"

   strings:
      $hex_string = { 010001002020000002002000a8100000010050414444494e47585850414444494e4750414444494e47585850414444494e4750414444494e4758585041444449 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
