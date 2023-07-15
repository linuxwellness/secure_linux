
rule n2319_129b86c9c8000912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2319.129b86c9c8000912"
     cluster="n2319.129b86c9c8000912"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="miner coinminer script"
     md5_hashes="['09cd9ba7da14dfec65009be6142782a11259e012','eb106fa873ca90825e6bb561505faf5984d631f9','3e90d7e24d92b1eac1f62dd7d03c9cb3690d20d0']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n2319.129b86c9c8000912"

   strings:
      $hex_string = { 434f4e4649473d7b4c49425f55524c3a2268747470733a2f2f636f696e686976652e636f6d2f6c69622f222c41534d4a535f4e414d453a22776f726b65722d61 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
