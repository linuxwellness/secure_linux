
rule m3e9_5492a4a54b534876
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.5492a4a54b534876"
     cluster="m3e9.5492a4a54b534876"
     cluster_size="14"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="backdoor plite gupboot"
     md5_hashes="['149249771d140c8204a507a1897a4716','203e49106a39880420a399c5ff48734a','ff8dc351148b3b4e6cb376443bc52c1e']"

   strings:
      $hex_string = { 0427a83d41febbb7ebf606522c05877518ce0a688d9792408c3003c8e5f7658bcdea5df332db6951b4b24f4dd60b7c24f822fbd87db1bf6715d1a3f2086e5bd2 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
