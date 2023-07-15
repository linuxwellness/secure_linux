
rule m3f1_149950e1c2000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f1.149950e1c2000b32"
     cluster="m3f1.149950e1c2000b32"
     cluster_size="20"
     filetype = "application/zip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="androidos appad triada"
     md5_hashes="['15b90eaf9ff75a8aafa48af1f16b1d50','28641818a6aa997bdbd873df0d6a360f','c54058090311052381e163d6bc5a29ce']"

   strings:
      $hex_string = { a46c53f5e809e21581ac40cc603008a8be6a9ee097236276fa8e2cbb5ee5395273998aa7c404f31d593e718f5827aeafba832be681659b56dc175d7ef2455c20 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
