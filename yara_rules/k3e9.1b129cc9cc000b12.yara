
rule k3e9_1b129cc9cc000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.1b129cc9cc000b12"
     cluster="k3e9.1b129cc9cc000b12"
     cluster_size="4"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="rincux ddos stormattack"
     md5_hashes="['098528d28e907f6a1e458a62fbf64464','84b25b2012ffc6802415c6928a65424f','ffd30bd40f054cb76661f20c1ea4931e']"

   strings:
      $hex_string = { bdcc42812a8c34ae8b9283051449ec9ff08f12940ab328bed84c49880762ca2497298ec40e21236e4fc6fbe9e8ea93ce448a3d156f1fd93f844709de48c5a304 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
