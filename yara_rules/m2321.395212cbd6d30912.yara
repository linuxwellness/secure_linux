
rule m2321_395212cbd6d30912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.395212cbd6d30912"
     cluster="m2321.395212cbd6d30912"
     cluster_size="8"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="small generickd upatre"
     md5_hashes="['1202ddc4c459505501f53151f76a9de6','3f9fa8fe3b405d6180bb355d26c3768c','ef755adf7c2b43c04f581e47888cfdf0']"

   strings:
      $hex_string = { a5c8857be7b803ea7d101b0d715231a35d554cac07d8462cefbc06bb04fc8ade2ad2d73ed149b735ed901c10f3e56ba069486de69cb41930bab609aeb1a43a7c }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
