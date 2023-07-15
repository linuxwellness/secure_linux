
rule k2319_1a1856b9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.1a1856b9c8800b12"
     cluster="k2319.1a1856b9c8800b12"
     cluster_size="87"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['24030dddaed06165a2802a51df7146d77a9da7cb','d5e25fcf7d02870f3d3a7d5a639e8e907d36e701','446dd42fdb9e9e55f3ada4c58c580f58d134418c']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.1a1856b9c8800b12"

   strings:
      $hex_string = { 3a283132392c3134302e334531292929627265616b7d3b7661722042366b36483d7b27703367273a226e6473222c27683948273a66756e6374696f6e28572c70 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
