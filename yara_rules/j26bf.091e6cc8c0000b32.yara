
rule j26bf_091e6cc8c0000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j26bf.091e6cc8c0000b32"
     cluster="j26bf.091e6cc8c0000b32"
     cluster_size="116"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="zusy malicious starter"
     md5_hashes="['7490702998d8ce0697318e97f2254665fbcc4cbc','54e8a36d3158cdd20bbca7bf85131efd52c8ff23','a4b882e855dd65b90329d1a1a00ced0ac9f7a1f2']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=j26bf.091e6cc8c0000b32"

   strings:
      $hex_string = { 734f626a65637450726f7669646572004170706c69636174696f6e00576562536572766963657300457175616c73006f0047657448617368436f646500547970 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
