
rule n3ec_11b04a56c2210112
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ec.11b04a56c2210112"
     cluster="n3ec.11b04a56c2210112"
     cluster_size="25"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="expiro kakavex blpei"
     md5_hashes="['0c9c726ca4017463efaaef05945cd6f9','1a5fbcaf93d411c9b6e05521c3838bd9','dc792b21de725ef0aa2ba1ec7796efde']"

   strings:
      $hex_string = { c3b0b1a2ada7000400d2b4a0b7b70006008bf8fff9e8fbf2000800fa8c898a8893948e9c00070054203b2124243126000400fd8f9c9399000a0061021315050d }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
