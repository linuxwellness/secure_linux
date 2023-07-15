
rule k2319_295a86b9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.295a86b9c8800b12"
     cluster="k2319.295a86b9c8800b12"
     cluster_size="13"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['e69c19ae62726ea88a3f10e61753270770c34cc8','964fd7d92f24f11d9979e29972d0d5346645a416','40459a3806ecf86e32fc363dec664ae3a1a8d960']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.295a86b9c8800b12"

   strings:
      $hex_string = { 66696e6564297b72657475726e20505b6a5d3b7d76617220753d28283132352e2c322e30374532293c3d283134362c3078323343293f2835332e2c3078636339 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
