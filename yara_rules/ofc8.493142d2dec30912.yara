
rule ofc8_493142d2dec30912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=ofc8.493142d2dec30912"
     cluster="ofc8.493142d2dec30912"
     cluster_size="6"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="smspay riskware shedun"
     md5_hashes="['d52481df0f2e82b65f6d806e09ffe0fa60bcde1d','87cf3cc2f3235e2d0bfd97ba4c3be30fc4385e8b','790f98952d50035eaf07ea6f5d0c081c628ff523']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=ofc8.493142d2dec30912"

   strings:
      $hex_string = { 30ced0f7a35cfa93e3559a7c13c8ef1007deeccd7b965892fb69000ca553e124c18678c63de5df042fcb9d7a50dc9b1c017f02672e656e270dc0db8e423a0e18 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
