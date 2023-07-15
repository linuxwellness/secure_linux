
rule k2319_291295a1c2000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.291295a1c2000b32"
     cluster="k2319.291295a1c2000b32"
     cluster_size="10"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['2aefc589067e282f1caaf072a5925961ce20f8db','4ff0221fc9a50a3431b630fb28989b06ee2196a8','648dafdc91b05b2bb86908a759e0f4cd0d50462d']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.291295a1c2000b32"

   strings:
      $hex_string = { 2830783231422c322e38314532292929627265616b7d3b766172207334473d7b27693534273a362c27613634273a2249222c2751273a66756e6374696f6e2847 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
