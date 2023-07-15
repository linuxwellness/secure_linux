
rule k2319_295479e9ca000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.295479e9ca000b32"
     cluster="k2319.295479e9ca000b32"
     cluster_size="13"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['04935f068823a03d50d0c5bf1e759d8e5018e80b','a71f0302068dd0eb898b69eb7426a7fa55d59451','ad3813d6c73110b839291dcc9cda64952e20ef9f']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.295479e9ca000b32"

   strings:
      $hex_string = { 213d3d756e646566696e6564297b72657475726e20745b765d3b7d76617220543d28283134392e2c32352e354531293c3d33352e3f28307844462c227922293a }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
