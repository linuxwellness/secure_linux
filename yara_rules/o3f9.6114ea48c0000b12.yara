
rule o3f9_6114ea48c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3f9.6114ea48c0000b12"
     cluster="o3f9.6114ea48c0000b12"
     cluster_size="89"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="lyposit zusy malicious"
     md5_hashes="['0441eeb9523d3be4d214768c3949e2d4','0b2c8cd94bbdff60b052ccba627a72aa','a9486692d32428d296725f5433ff149c']"

   strings:
      $hex_string = { 65f56bbaf35210f02a85f80429ca614ee2aae988cb6a1258ef11b83cda3ef7a6b1bffd7b30fff9b9927d7371fc20873d74453b1f535b28c6b49e691c050e259a }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
