
rule k2321_29259123d9eb1932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.29259123d9eb1932"
     cluster="k2321.29259123d9eb1932"
     cluster_size="5"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vobfus symmi vbkrypt"
     md5_hashes="['72059c6132926219661608e88146670c','b1e87b8f881e678f1e9d0dbe8cb27e85','f72e55298fe6eb4392451a97d8fcddcb']"

   strings:
      $hex_string = { a6c4d95dae441f1d0305b360409dafb23ff19333aba00b361b9d0fba0a79566c098f5a396bffd1b84e4ac93a2e7a8e3568c5c845a2e34bdcccf6df4c65ecc3d8 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
