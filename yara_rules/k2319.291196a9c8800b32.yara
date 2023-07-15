
rule k2319_291196a9c8800b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.291196a9c8800b32"
     cluster="k2319.291196a9c8800b32"
     cluster_size="12"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['a602444d6ff90966cfec04962edb207f87d759a4','c83e38980976a9a030fd4283072fdab2ea343c6d','1d4910b030d05f92a8053ed0868e9e12bba69c33']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.291196a9c8800b32"

   strings:
      $hex_string = { 5d213d3d756e646566696e6564297b72657475726e20785b6b5d3b7d76617220513d2833392e3c2839312e2c30784238293f283132362c307863633965326435 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
